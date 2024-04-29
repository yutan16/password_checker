import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(
            f'ERROR Fetching: {response.status_code}, Check the API and try again.')
    return response


def count_pass_leaks(hashes, tail_hash):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == tail_hash:
            return count
    return 0


def pwned_api_checker(password):
    sha1_pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1_pass[:5], sha1_pass[5:]
    response = request_api_data(first5_char)
    print(response)  # 200 means its working 400 means its an error
    return count_pass_leaks(response, tail)


def main_password_checker(args):
    for password in args:
        count = pwned_api_checker(password)
        if count:
            print(
                f'Your password ({password}) was FOUND {count} many times! Please make sure to strengthen your password!')
        else:
            print(f'Your password ({password}) was NOT FOUND! Great choice!')
    return print('===================================DONE!===================================')


main_password_checker(sys.argv[1:])
