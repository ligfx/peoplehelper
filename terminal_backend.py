import subprocess


def notification(message):
    print("NOTIFY: %s" % message)


def error(message):
    print("ERROR: %s" % message)


def question(message):
    return input(message + " ").strip()
