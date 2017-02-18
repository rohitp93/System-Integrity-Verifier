# coding=utf-8
import argparse
import hashlib
import json
import os
import pwd
import sys
import textwrap
from datetime import datetime
from grp import getgrgid
from pprint import pprint

parser = argparse.ArgumentParser(
    description=textwrap.dedent('''Initialization --> siv.py -i -D 'dir' -V 'ver_file' -R 'rep_file' -H 'hash'
                                ----------------------------------------------------------------------------
                                Verification  --> siv.py -v -D 'dir' -V 'ver_file' -R 'rep_file' '''))
arg_group = parser.add_mutually_exclusive_group()
arg_group.add_argument("-i", "--initialize", action="store_true", help="Initialization mode")
arg_group.add_argument("-v", "--verify", action="store_true", help="Verification mode")
parser.add_argument("-D", "--monitored_directory", type=str, help="Give a Directory that needs to be monitored")
parser.add_argument("-V", "--verification_file", type=str,
                        help="Give a Verification File that can store records of each file in the monitored directory")
parser.add_argument("-R", "--report_file", type=str, help="Give a Report File to store final report")
parser.add_argument("-H", "--hash_function", type=str, help="Hash Algorithm supported are 'SHA-1' and 'MD-5' ")

args = parser.parse_args()

mon = args.monitored_directory
ver = args.verification_file
rep = args.report_file
alg = args.hash_function

if args.initialize:

    # Initialization mode
    print("Initialization Mode\n")
    start = datetime.utcnow()

    # Check if Monitored directory exists
    if os.path.isdir(mon) == 1:
        print("Monitored Directory exists\n")

        # Check the algorithm requested for hashing
        if alg == "SHA-1" or alg == "MD-5":

            i = 0  # Number of files parsed
            j = 0  # Number of dirs parsed
            det = []
            det_dir = {}
            det_file = {}
            det_hash = {}

            # Check if Verification and Report files exits
            if os.path.isfile(ver) == 1 and os.path.isfile(rep) == 1:
                print("Verification and Report files exist\n")

                # Check if Verification and Report files are outside monitored directory
                if (os.path.commonprefix([mon, ver]) == mon) or (os.path.commonprefix([mon, rep]) == mon):
                    print("Verification and Report file must be outside\n")
                    sys.exit()
                else:
                    print("Verification and Report files are outside\n")

            else:
                os.open(ver, os.O_CREAT, mode=0o777)
                os.open(rep, os.O_CREAT, mode=0o0777)
                print("Verification or Report file does not exists and is created now\n")

                # Check if Verification and Report files are outside monitored directory
                if (os.path.commonprefix([mon, ver]) == mon) or (os.path.commonprefix([mon, rep]) == mon):
                    print("Verification and Report file must be outside\n")
                    sys.exit()
                else:
                    print("Verification and Report files are outside\n")

            # Ask user whether to overwrite Verification or report files otherwise exit
            choice = input("Do you want to overwrite y/n: ")

            if choice == "n":
                sys.exit()

            elif choice == "y":

                for subdir, dirs, files in os.walk(mon):

                    for fds in dirs:
                        i += 1
                        path = os.path.join(subdir, fds)
                        size = os.path.getsize(path)
                        user = pwd.getpwuid(os.stat(path).st_uid).pw_name
                        group = getgrgid(os.stat(path).st_gid).gr_name
                        recent = datetime.fromtimestamp(os.stat(path).st_mtime).strftime('%c')
                        access = oct(os.stat(path).st_mode & 0o777)

                        det_dir[path] = {
                            "size": size, "user": user, "group": group, "recent": recent, "access": access
                        }

                    for file in files:
                        j += 1
                        fpath = os.path.join(subdir, file)
                        fsize = os.stat(fpath).st_size
                        fuser = pwd.getpwuid(os.stat(fpath).st_uid).pw_name
                        fgroup = getgrgid(os.stat(fpath).st_gid).gr_name
                        frecent = datetime.fromtimestamp(os.stat(fpath).st_mtime).strftime('%c')
                        faccess = oct(os.stat(fpath).st_mode & 0o777)

                        # Message digest computed with MD-5
                        if alg == "MD-5":
                            htype = "md5"
                            h = hashlib.md5()
                            with open(fpath, 'rb') as mfile:
                                buf = mfile.read()
                                h.update(buf)
                                message = h.hexdigest()

                        # Message digest computed with SHA-1
                        else:
                            htype = "sha1"
                            h = hashlib.sha1()
                            with open(fpath, 'rb') as hfile:
                                buf = hfile.read()
                                h.update(buf)
                                message = h.hexdigest()

                        det_file[fpath] = {"size": fsize, "user": fuser, "group": fgroup, "recent": frecent,
                                           "access": faccess, "hash": message}

                det.append(det_dir)
                det_hash = {"hash_type": htype}
                det.append(det_file)
                det.append(det_hash)
                json_string = json.dumps(det, indent=2, sort_keys=True)

                print("\nVerification File generated")

                # Write into Verification file
                with open(ver, "w") as vf:
                    vf.write(json_string)

                print("\nReport File generated")

                # Write into Report file
                with open(rep, "w") as rf:
                    end = datetime.utcnow()
                    rf.write(
                        "Initialization mode complete \n\nMonitored directory = " + mon + "\nVerification file =" + ver + "\nNumber of directories parsed =" + str(
                            i) + "\nNumber of files parsed = " + str(j) + "\nTime taken = " + str(end - start) + "\n")
            else:
                print("Invalid choice")
                sys.exit()
        else:
            print("Hash not supported")
            sys.exit()
    else:
        print("Monitored directory does not exist")
        sys.exit()

elif args.verify:
    # Verification Mode
    start = datetime.utcnow()

    print("Verification Mode\n")

    if os.path.isfile(ver) == 1:
        print("Verification File exists\n")

        # Check if Verification and Report files are outside monitored directory
        if (os.path.commonprefix([mon, ver]) == mon) or (os.path.commonprefix([mon, rep]) == mon):
            print("Verification and Report file must be outside\n")
            sys.exit()
        else:
            print("Verification and Report files are outside\n")

    else:
        print("Verification file doesn't exist")
        sys.exit()

    i = 0  # Number of dirs parsed
    j = 0  # Number of files parsed
    k = 0  # Number of warnings

    with open(ver) as input_file:
        json_decode = json.load(input_file)

    with open(rep, "a") as rep_write:
        rep_write.write("\nVerification Mode begin\n")

    for each_file in json_decode[2]:
        htype = each_file[2]

    with open(rep, "a") as rep_write:

        for subdir, dirs, files in os.walk(mon):

            for fds in dirs:
                i += 1
                path = os.path.join(subdir, fds)
                size = os.stat(path).st_size
                user = pwd.getpwuid(os.stat(path).st_uid).pw_name
                group = getgrgid(os.stat(path).st_gid).gr_name
                recent = datetime.fromtimestamp(os.stat(path).st_mtime).strftime('%c')
                access = oct(os.stat(path).st_mode & 0o777)
                print("Dir   " + path + "\n")

                if path in json_decode[0]:

                    if size != json_decode[0][path]['size']:
                        rep_write.write("\nWarning dir " + path + " has different size\n")
                        k += 1
                    if user != json_decode[0][path]['user']:
                        rep_write.write("\nWarning dir " + path + " has different user\n")
                        k += 1
                    if group != json_decode[0][path]['group']:
                        rep_write.write("\nWarning dir " + path + " has different group\n")
                        k += 1
                    if recent != json_decode[0][path]['recent']:
                        rep_write.write("\nWarning dir " + path + " has different modification date\n")
                        k += 1
                    if access != json_decode[0][path]['access']:
                        rep_write.write("\nWarning dir " + path + " has modified access rights\n")
                        k += 1
                else:
                    rep_write.write("\nWarning dir " + path + " has been added\n")
                    k += 1

        for each_prev_dir in json_decode[0]:

            if os.path.isdir(each_prev_dir) == 0:
                rep_write.write("\nWarning dir " + each_prev_dir + " has been deleted\n")
                k += 1

        for subdir, dirs, files in os.walk(mon):

            for file in files:
                j += 1
                fpath = os.path.join(subdir, file)
                fsize = os.stat(fpath).st_size
                fuser = pwd.getpwuid(os.stat(fpath).st_uid).pw_name
                fgroup = getgrgid(os.stat(fpath).st_gid).gr_name
                frecent = datetime.fromtimestamp(os.stat(fpath).st_mtime).strftime('%c')
                faccess = oct(os.stat(fpath).st_mode & 0o777)
                print("File   " + fpath + "\n")
                # Message digest computed with MD-5
                if htype == "md5":
                    h = hashlib.md5()
                    with open(fpath, 'rb') as mfile:
                        buf = mfile.read()
                        h.update(buf)
                        message = h.hexdigest()

                # Message digest computed with SHA-1
                else:
                    h = hashlib.sha1()
                    with open(fpath, 'rb') as hfile:
                        buf = hfile.read()
                        h.update(buf)
                        message = h.hexdigest()

                if fpath in json_decode[1]:

                    if fsize != json_decode[1][fpath]['size']:
                        rep_write.write("\nWarning file " + fpath + " has different size\n")
                        k += 1
                    if fuser != json_decode[1][fpath]['user']:
                        rep_write.write("\nWarning file " + fpath + " has different user\n")
                        k += 1
                    if fgroup != json_decode[1][fpath]['group']:
                        rep_write.write("\nWarning file " + fpath + " has different group\n")
                        k += 1
                    if frecent != json_decode[1][fpath]['recent']:
                        rep_write.write("\nWarning file " + fpath + " has different modification date\n")
                        k += 1
                    if faccess != json_decode[1][fpath]['access']:
                        rep_write.write("\nWarning file " + fpath + " has modified access rights\n")
                        k += 1
                    if message != json_decode[1][fpath]['hash']:
                        rep_write.write("\nWarning file " + fpath + " different message digest\n")
                        k += 1
                else:
                    rep_write.write("\nWarning dir " + fpath + " has been added\n")
                    k += 1

        for each_prev_file in json_decode[1]:
            if os.path.isfile(each_prev_file) == 0:
                rep_write.write("\nWarning dir " + each_prev_file + " has been deleted\n")
                k += 1

    # Write into Report file
    with open(rep, "a") as rf:
        end = datetime.utcnow()
        rf.write(
            "\nVerification mode complete \n\nMonitored directory = " + mon + "\nVerification file =" + ver + "\nNumber of directories parsed =" + str(
                i) + "\nNumber of files parsed = " + str(j) + "\nTotal Warnings = " + str(k) + "\nTime taken = " + str(
                end - start) + "\n")

    print("Report File generated")
