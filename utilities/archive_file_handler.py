import os
import zipfile
import timeit
from multiprocessing import Process
from utilities import constants
"""
Unpacks the APKs present in the RAW_FILES_PATH variable.
The RAW_FILES_PATH directory should contain two folders, namely: benign & malicious
Tags the unpacked APK based on the directory it was found in to benign and malicious.
"""


def unpack_apk_files(filename, tag):
    password_zip = zipfile.ZipFile(constants.RAW_FILES_PATH + tag + "/" + filename, mode="r")
    password_zip.extractall(path=constants.UNPACKED_FILES_PATH + tag + "_" + filename)
    password_zip.close()


def execute_unzip():
    start_time = timeit.default_timer()
    tasks = []
    for root, directory, files in os.walk(constants.RAW_FILES_PATH):
        for file in files:
            # print(type(root))
            if file.endswith('.apk') and 'benign' in root:
                p = Process(target=unpack_apk_files, args=(file, 'benign'))
                tasks.append(p)
                p.start()
            elif file.endswith('.apk') and 'malicious' in root:
                p = Process(target=unpack_apk_files, args=(file, 'malicious'))
                tasks.append(p)
                p.start()
            else:
                print('Unknown packaging. Cannot unpack the archive.')
            # print(file)

    for task in tasks:
        task.join()
    elapsed_time = timeit.default_timer()
    print("Finished Unzipping the apk files...")
    print("Time Taken: (in Secs)", elapsed_time - start_time)
