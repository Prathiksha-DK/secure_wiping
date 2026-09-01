#include <windows.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <winioctl.h>
#include <time.h>
#include <stdlib.h>

// A large buffer size can improve performance
#define BUFFER_SIZE (1024 * 1024) // 1 MB
#define DRIVE_LIST_LIMIT 10 // Max Physical Drives to check (0 to 9)

// Global seed for randomness
static unsigned int g_seed = 0;

/**
 * @brief Clears the input buffer to prevent leftover newlines from interfering with getchar().
 */
void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

/**
 * @brief Prints the current progress percentage to the console.
 * * @param current The number of bytes written so far.
 * @param total The total size of the disk in bytes.
 */
void print_progress(long long current, long long total, int pass_num, int total_passes) {
    if (total <= 0) return;
    float percentage = 100.0 * current / total;
    printf("\r[Pass %d of %d] Progress: %.2f%% (%lld / %lld bytes)", 
           pass_num, total_passes, percentage, current, total);
    fflush(stdout);
}

/**
 * @brief Lists available logical and potential physical drives.
 */
void list_devices() {
    printf("\n--- Available Logical Drives (e.g., 'E') ---\n");
    DWORD drive_mask = GetLogicalDrives();
    char drive_letter = 'A';
    for (int i = 0; i < 26; i++) {
        if ((drive_mask >> i) & 1) {
            char root_path[4] = {drive_letter + i, ':', '\\', '\0'};
            UINT drive_type = GetDriveTypeA(root_path);
            const char* type_str;
            switch (drive_type) {
                case DRIVE_FIXED: type_str = "Fixed (HDD/SSD)"; break;
                case DRIVE_REMOVABLE: type_str = "Removable (USB/Flash)"; break;
                case DRIVE_CDROM: type_str = "CD-ROM"; break;
                case DRIVE_REMOTE: type_str = "Network Drive"; break;
                default: type_str = "Other/Unknown"; break;
            }
            printf("  - %c: (%s)\n", drive_letter + i, type_str);
        }
    }
    
    printf("\n--- Potential Physical Drives (e.g., 'PhysicalDrive1') ---\n");
    printf("  (Physical drives wipe the entire disk, including partitions)\n");
    for (int i = 0; i < DRIVE_LIST_LIMIT; i++) {
        char phys_name[30];
        snprintf(phys_name, sizeof(phys_name), "\\\\.\\PhysicalDrive%d", i);
        // Try opening the handle with minimal rights just to check existence
        HANDLE hDevice = CreateFileA(phys_name, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hDevice != INVALID_HANDLE_VALUE) {
            printf("  - PhysicalDrive%d (Disk %d)\n", i, i);
            CloseHandle(hDevice);
        }
    }
    printf("----------------------------------------------------------\n");
}

/**
 * @brief Performs a single data wiping pass on the device.
 * * @param hDevice Handle to the opened device.
 * @param disk_size Total size of the disk in bytes.
 * @param pattern_type 0=Zeros, 1=Ones, 2=Random.
 * @param pass_num Current pass number (for display).
 * @param total_passes Total passes in the sequence (for display).
 * @return int 0 on success, 1 on failure.
 */
int perform_wipe_pass(HANDLE hDevice, long long disk_size, int pattern_type, int pass_num, int total_passes) {
    BYTE* buffer = (BYTE*)malloc(BUFFER_SIZE);
    if (!buffer) {
        fprintf(stderr, "\nFailed to allocate memory for buffer in pass %d.\n", pass_num);
        return 1;
    }

    const char* pattern_name;
    switch (pattern_type) {
        case 0:
            pattern_name = "Zero Fill (0x00)";
            memset(buffer, 0x00, BUFFER_SIZE);
            break;
        case 1:
            pattern_name = "One Fill (0xFF)";
            memset(buffer, 0xFF, BUFFER_SIZE);
            break;
        case 2:
            pattern_name = "Random Data";
            break;
        default:
            pattern_name = "Unknown Pattern";
            break;
    }

    printf("\n\n--- Starting Pass %d of %d: %s ---\n", pass_num, total_passes, pattern_name);
    
    // Move pointer to the start of the device
    if (SetFilePointer(hDevice, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        fprintf(stderr, "\nError resetting file pointer for pass %d. GetLastError()=%lu\n", pass_num, GetLastError());
        free(buffer);
        return 1;
    }

    long long total_bytes_written = 0;
    DWORD bytes_written_in_call;
    
    // Seed the random number generator only once for all passes
    if (pattern_type == 2 && g_seed == 0) {
        g_seed = (unsigned int)time(NULL);
        srand(g_seed);
    }
    
    // Start timing the pass
    clock_t start_time = clock();

    while (total_bytes_written < disk_size) {
        long long remaining_bytes = disk_size - total_bytes_written;
        DWORD bytes_to_write = (remaining_bytes < BUFFER_SIZE) ? (DWORD)remaining_bytes : BUFFER_SIZE;

        if (pattern_type == 2) {
            // Fill with new random data on each iteration for Pass 3
            for (DWORD i = 0; i < bytes_to_write; ++i) {
                buffer[i] = (BYTE)(rand() % 256);
            }
        }
        
        if (!WriteFile(hDevice, buffer, bytes_to_write, &bytes_written_in_call, NULL)) {
            // If WriteFile fails, it's usually another permissions issue, or the drive was disconnected.
            DWORD last_error = GetLastError();
            fprintf(stderr, "\n\n******************************************************************\n");
            fprintf(stderr, "!!! FATAL ERROR: Write failed at offset %lld. GetLastError()=%lu\n", total_bytes_written, last_error);
            if (last_error == 5) { // Error 5 is Access Denied
                 fprintf(stderr, "!!! POSSIBLE REASON: The device might be currently in use by the system.\n");
            }
            fprintf(stderr, "******************************************************************\n");
            free(buffer);
            return 1;
        }

        total_bytes_written += bytes_written_in_call;
        print_progress(total_bytes_written, disk_size, pass_num, total_passes);
    }
    
    clock_t end_time = clock();
    double time_spent = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    printf("\r[Pass %d of %d] Progress: 100.00%% (%lld / %lld bytes) | Time: %.2f seconds\n", 
           pass_num, total_passes, disk_size, disk_size, time_spent);

    free(buffer);
    return 0; // Success
}

int main() {
    char device_name[100];
    char full_device_path[120];
    int wipe_method;
    char confirm1[10], confirm2[10];

    printf("--- DISK WIPE UTILITY (WINDOWS) ---\n\n");
    printf("!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!\n");
    printf("! This program will IRREVERSIBLY DESTROY ALL DATA on the selected drive.\n");
    printf("! Use with extreme caution. Ensure you have selected the correct drive.\n");
    printf("! This requires ADMINISTRATOR privileges to run.\n");
    printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

    // List available drives first
    list_devices();

    printf("Enter the drive to wipe (e.g., 'E' for E:, or 'PhysicalDrive1' for an entire disk): ");
    // Clear buffer from previous inputs if running in a loop/script, but mainly for safety
    clear_input_buffer(); 
    scanf("%99s", device_name);

    printf("Select a wipe method:\n");
    printf("  1. Single Pass - Zeros (Quick Clean)\n");
    printf("  2. Single Pass - Ones\n");
    printf("  3. Single Pass - Random Data (Standard Security)\n");
    printf("  4. 3-Pass DoD-like Secure Wipe (Zeros, Ones, Random) <--- Recommended\n");
    printf("Enter your choice (1-4): ");
    scanf("%d", &wipe_method);

    if (wipe_method < 1 || wipe_method > 4) {
        printf("Invalid choice. Aborting.\n");
        // Pause before exiting on input error
        printf("\n\nPress ENTER to exit...");
        clear_input_buffer(); 
        getchar(); 
        return 1;
    }

    // Construct the full path for the CreateFile API
    if (strlen(device_name) == 1 && isalpha(device_name[0])) {
        // Logical drive like C, D, E
        snprintf(full_device_path, sizeof(full_device_path), "\\\\.\\%c:", toupper(device_name[0]));
    } else {
        // Physical drive like PhysicalDrive0
        snprintf(full_device_path, sizeof(full_device_path), "\\\\.\\%s", device_name);
    }

    printf("\n!! FINAL CONFIRMATION !!\n");
    printf("You are about to wipe all data from '%s' using method %d.\n", full_device_path, wipe_method);
    printf("This action CANNOT be undone.\n");
    printf("To confirm, type 'WIPE' and press Enter: ");
    scanf("%9s", confirm1);

    if (strcmp(confirm1, "WIPE") != 0) {
        printf("Confirmation failed. Aborting.\n");
        printf("\n\nPress ENTER to exit...");
        clear_input_buffer(); 
        getchar(); 
        return 1;
    }

    printf("Are you absolutely sure? Type 'YES' to proceed: ");
    scanf("%9s", confirm2);

    if (strcmp(confirm2, "YES") != 0) {
        printf("Final confirmation failed. Aborting.\n");
        printf("\n\nPress ENTER to exit...");
        clear_input_buffer(); 
        getchar(); 
        return 1;
    }
    
    printf("\nOpening device %s...\n", full_device_path);
    HANDLE hDevice = CreateFileA(full_device_path,
                                 GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 NULL,
                                 OPEN_EXISTING,
                                 0,
                                 NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD last_error = GetLastError();
        fprintf(stderr, "\n******************************************************************\n");
        fprintf(stderr, "!!! ERROR: Failed to open device. GetLastError()=%lu\n", last_error);
        fprintf(stderr, "!!! COMMON REASON (Error 5 - Access Denied): You must be running this program as ADMINISTRATOR.\n");
        fprintf(stderr, "******************************************************************\n");
        // Pause before exiting on error
        printf("\n\nPress ENTER to exit...");
        clear_input_buffer(); 
        getchar(); 
        return 1;
    }
    
    // Get disk size
    GET_LENGTH_INFORMATION disk_size_info;
    DWORD bytesReturned;
    if (!DeviceIoControl(hDevice, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &disk_size_info, sizeof(disk_size_info), &bytesReturned, NULL)) {
        DWORD last_error = GetLastError();
        fprintf(stderr, "\n******************************************************************\n");
        fprintf(stderr, "!!! ERROR: Failed to get disk size. GetLastError()=%lu\n", last_error);
        if (last_error == 5) { // Error 5 is Access Denied
             fprintf(stderr, "!!! COMMON REASON (Error 5 - Access Denied): You must be running this program as ADMINISTRATOR.\n");
        }
        fprintf(stderr, "******************************************************************\n");
        CloseHandle(hDevice);
        // Pause before exiting on error
        printf("\n\nPress ENTER to exit...");
        clear_input_buffer(); 
        getchar(); 
        return 1;
    }
    
    long long disk_size = disk_size_info.Length.QuadPart;
    printf("Device opened. Total size: %.2f GB (%lld bytes)\n", (double)disk_size / (1024.0*1024.0*1024.0), disk_size);

    int result = 0;

    if (wipe_method == 4) {
        // 3-Pass DoD-like Secure Wipe: Zeros, Ones, Random
        printf("\n\n*** Initiating 3-Pass DoD-like Secure Wipe ***\n");
        // Pass 1: Zeros (Pattern Type 0)
        result |= perform_wipe_pass(hDevice, disk_size, 0, 1, 3);
        // Pass 2: Ones (Pattern Type 1)
        result |= perform_wipe_pass(hDevice, disk_size, 1, 2, 3);
        // Pass 3: Random (Pattern Type 2)
        result |= perform_wipe_pass(hDevice, disk_size, 2, 3, 3);
        
        if (result == 0) {
            printf("\n\n--- 3-Pass Secure Wipe SUCCESSFULLY COMPLETED ---\n");
        } else {
            fprintf(stderr, "\n\n--- 3-Pass Secure Wipe FAILED during one or more passes ---\n");
        }

    } else {
        // Single Pass Wipe (Methods 1, 2, 3)
        printf("\n\n*** Initiating Single Pass Wipe ***\n");
        result = perform_wipe_pass(hDevice, disk_size, wipe_method - 1, 1, 1);
        
        if (result == 0) {
            printf("\n\n--- Single Pass Wipe SUCCESSFULLY COMPLETED ---\n");
        } else {
            fprintf(stderr, "\n\n--- Single Pass Wipe FAILED ---\n");
        }
    }
    
    CloseHandle(hDevice);

    // VITAL: Pause the console before exiting so the user can read the results/errors
    printf("\n\nPress ENTER to exit...");
    clear_input_buffer(); 
    getchar(); 
    
    return result;
}
