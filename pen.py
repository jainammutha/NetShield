import os
import wmi
import pythoncom

def find_usb_storage_with_secure_file(expected_hash):
    pythoncom.CoInitialize()  # Initialize the COM library for the current thread
    c = wmi.WMI()
    valid_device_found = False

    for usb_device in c.Win32_DiskDrive():
        if usb_device.InterfaceType == "USB":
            for partition in usb_device.associators("Win32_DiskDriveToDiskPartition"):
                for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                    drive_letter = logical_disk.DeviceID
                    secure_file_path = os.path.join(drive_letter + "\\", "auth_key.txt")

                    if os.path.isfile(secure_file_path):
                        with open(secure_file_path, "r") as file:
                            file_content = file.read().strip()

                        if file_content == expected_hash:
                            print(f"Authentication successful! Found valid hash in {secure_file_path}")
                            valid_device_found = True
                        else:
                            print(f"Authentication failed: Hash mismatch in {secure_file_path}")
                    if valid_device_found:
                        break
        if valid_device_found:
            break

    if not valid_device_found:
        print("Authentication failed: Secure file not found or hash mismatch.")

    pythoncom.CoUninitialize()  # Uninitialize the COM library for the current thread
