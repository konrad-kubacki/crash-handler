// Windows includes.
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// Minidump.
#include <Dbghelp.h>
#pragma comment(lib, "Dbghelp.lib")

#include <cstdio>

// These are the event names used for communication between handler and child
// process.
char CrashOccuredEventName[] = "Local\\CrashOccurredEvent";
char CrashHandledEventName[] = "Local\\CrashHandledEvent";

// Name for the memory mapping that will hold crash data.
char CrashDumpMappingName[]    = "Local\\CrashDumpMapping";

// Structure to transfer the necessary crash data. We copy up to
// MAX_EXCEPTION_CHAIN_DEPTH records.
const int MAX_EXCEPTION_CHAIN_DEPTH = 10;
struct CrashData {
  ::DWORD threadId;
  ::CONTEXT contextRecord;
  ::DWORD numExceptionRecords;
  ::EXCEPTION_RECORD exceptionRecords[MAX_EXCEPTION_CHAIN_DEPTH];
};

// This are the child (client) handles used by the exception handler.
::HANDLE Client_CrashEventOccuredHandle = INVALID_HANDLE_VALUE;
::HANDLE Client_CrashEventHandledHandle = INVALID_HANDLE_VALUE;

// If this flag is not present, assume we need to run the crash handler first.
char CrashHandlerCommandLine[] = "--under-crash-handler";

// This exception handler is run in the child process. It just signals the crash
// to the parent.
::LONG our_exception_handler(::LPEXCEPTION_POINTERS exception_info);
int app_main();

int main(int argc, char *argv[]) {
  bool is_under_crash_handler = false;
  for (int i = 0; i < argc; ++i) {
    if (::strcmp(argv[i], CrashHandlerCommandLine) == 0) {
      is_under_crash_handler = true;
      break;
    }
  }

  if (is_under_crash_handler) {
    // Prepare our crash handler for signaling.
    Client_CrashEventOccuredHandle = ::OpenEventA(EVENT_ALL_ACCESS, FALSE, CrashOccuredEventName);
    Client_CrashEventHandledHandle = ::OpenEventA(EVENT_ALL_ACCESS, FALSE, CrashHandledEventName);
    ::SetUnhandledExceptionFilter(our_exception_handler);

    ::puts("We're under crash handler, start the actual program.");
    return app_main();
  }

  ::puts("We're not under crash handler yet, start it first.");

  // Create the events used for communication between handler and child. We
  // create them before starting the child process to avoid any data races.
  ::HANDLE crash_occured_handle = ::CreateEventA(0, /*bManualReset=*/TRUE, /*bInitialState=*/0, CrashOccuredEventName);
  ::HANDLE crash_handled_handle = ::CreateEventA(0, /*bManualReset=*/TRUE, /*bInitialState=*/0, CrashHandledEventName);

  char path_to_exe[MAX_PATH];
  ::GetModuleFileNameA(0, path_to_exe, MAX_PATH);
  ::puts(path_to_exe);

  ::STARTUPINFOA startup_info = {};
  startup_info.cb = sizeof(startup_info);
  ::PROCESS_INFORMATION process_information = {};

  ::BOOL success = ::CreateProcessA(path_to_exe,
                                    CrashHandlerCommandLine,
                                    /*lpProcessAttributes=*/ 0,
                                    /*lpThreadAttributes=*/  0,
                                    /*bInheritHandles= */    0,
                                    /*dwCreationFlags=*/     0,
                                    /*pEnvironment=*/        0,
                                    /*lpCurrentDirectory=*/  0,
                                    &startup_info,
                                    &process_information);

  if (!success) {
    ::puts("Failed to create process!");
  }

  // Wait for either the crash event or process termination.
  ::HANDLE handles[2] = { crash_occured_handle, process_information.hProcess };
  ::DWORD wait_result = ::WaitForMultipleObjects(2, handles, FALSE, INFINITE);
  if (wait_result == WAIT_OBJECT_0) {
    // Crash event signaled.
    ::CloseHandle(crash_occured_handle);
    ::puts("Got a crash event! Handling...");

    // Open the memory mapping to read crash data.
    ::HANDLE mapping = ::OpenFileMappingA(FILE_MAP_READ, FALSE, CrashDumpMappingName);
    if (mapping) {
        CrashData* data = (CrashData*)::MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, sizeof(CrashData));
        if (data) {
            // Open a file to write the minidump.
            ::HANDLE dump_file = CreateFileA("crashdump.dmp", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
            if (dump_file != INVALID_HANDLE_VALUE) {
                // Prepare exception info for MiniDumpWriteDump.
                ::MINIDUMP_EXCEPTION_INFORMATION mdei = {};
                mdei.ThreadId = data->threadId;
                ::EXCEPTION_POINTERS ep = {};
                ep.ExceptionRecord = data->exceptionRecords;
                ep.ContextRecord   = &data->contextRecord;
                mdei.ExceptionPointers = &ep;
                mdei.ClientPointers = FALSE;

                ::MiniDumpWriteDump(process_information.hProcess,
                                    process_information.dwProcessId,
                                    dump_file,
                                    MiniDumpNormal,
                                    &mdei,
                                    0,
                                    0);
                ::CloseHandle(dump_file);
            }
            ::UnmapViewOfFile(data);
        }
        ::CloseHandle(mapping);
    }

    ::SetEvent(crash_handled_handle);
    ::CloseHandle(crash_handled_handle);
  } else if (wait_result == WAIT_OBJECT_0 + 1) {
    // Child process ended normally.
    ::CloseHandle(crash_occured_handle);
    ::CloseHandle(crash_handled_handle);
    ::puts("Child process exited normally.");
  }

  ::puts("That's all, folks.");
  return 0;
}

::LONG our_exception_handler(::LPEXCEPTION_POINTERS exception_info) {
  ::puts("!!! Exception caugth!");

  // Prepare crash data. This is shared with the crash handler process.
  CrashData crash_data = {};
  crash_data.threadId = ::GetCurrentThreadId();
  // Deep copy the context.
  crash_data.contextRecord = *exception_info->ContextRecord;

  // Deep copy the exception record chain.
  ::EXCEPTION_RECORD const *src = exception_info->ExceptionRecord;
  int i = 0;
  while (src && i < MAX_EXCEPTION_CHAIN_DEPTH) {
      crash_data.exceptionRecords[i] = *src;
      crash_data.exceptionRecords[i].ExceptionRecord = 0;

      // "Rewire" the nested pointer: if there's a next record and room remains,
      // point into our array.
      if (src->ExceptionRecord && i < MAX_EXCEPTION_CHAIN_DEPTH - 1) {
          crash_data.exceptionRecords[i].ExceptionRecord = &crash_data.exceptionRecords[i+1];
      }

      src = src->ExceptionRecord;
      i += 1;
  }
  crash_data.numExceptionRecords = i;

  // Create a named memory mapping to share crash data with the parent.
  ::HANDLE mapping = ::CreateFileMappingA(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, sizeof(CrashData), CrashDumpMappingName);
  if (mapping) {
      CrashData *data = (CrashData*)::MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(CrashData));
      if (data) {
          *data = crash_data;
          ::UnmapViewOfFile(data);
      }
      // Do not close hMapping yet; keep it open so that the parent can open the mapping.
  }

  // Notify the crash handler.
  ::SetEvent(Client_CrashEventOccuredHandle);
  ::CloseHandle(Client_CrashEventOccuredHandle);
  ::puts("!!! Crash Signaled!");

  ::DWORD const HANDLER_TIMEOUT_MS = 5000;
  // Wait for crash handler to finish (within reasonable time, let's hope it did not crash as well!)
  ::WaitForSingleObject(Client_CrashEventHandledHandle, HANDLER_TIMEOUT_MS);
  ::puts("!!! Crash handled!");

  // Now safe to close the memory mapping handle.
  if (mapping) {
    ::CloseHandle(mapping);
  }

  // Terminate the process.
  ::TerminateProcess(::GetCurrentProcess(), 0);
  return EXCEPTION_EXECUTE_HANDLER;
}

int app_main() {
  ::puts("This is your actual application code.");

  // Simulate a crash.
  *((int*)0) = 0;

  return 0;
}
