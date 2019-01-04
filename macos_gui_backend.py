import subprocess


def notification(message):
    script = (
        """
      set message to "%s"
      display dialog message buttons {"OK"}
    """
        % message
    )
    proc = subprocess.run(
        "osascript",
        input=script,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    print(proc)


def error(message):
    script = """
      set kStopIcon to stop
      set message to "%s"
      display dialog message with title "Error" with icon kStopIcon buttons {"OK"}
    """ % message.replace(
        '"', '\\"'
    ).replace(
        "\n", "\\n"
    )
    proc = subprocess.run(
        "osascript",
        input=script,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    print(proc)


def question(message):
    result = b""
    script = (
        """
    display dialog "%s" default answer ""
    text returned of result
  """
        % message
    )
    while not result:
        proc = subprocess.run(
            "osascript",
            input=script,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if proc.returncode != 0:
            print(proc)
            myexit()
        result = proc.stdout.strip()
    return result
