import re
from bs4 import BeautifulSoup
import quopri
import email


def preprocess_email(email_content):
    # Parse the email content
    parser = email.parser.BytesParser()
    email_message = parser.parsebytes(email_content)

    ## Extract the subject
    subject = email_message['subject'] or "NO SUBJECT"

    ## Extract the email headers
    headers = email_message.items()
    # Convert the headers to a string
    header_string = "\n".join([f"{key}: {value}" for key, value in headers])

    ## Extract the email body
    body = ""
    if email_message.is_multipart():
        # If the email has multiple parts (e.g., text and HTML), we iterate through them
        for part in email_message.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain' or content_type == 'text/html':
              body += part.get_payload(decode=True).decode()
    else:
        # If the email is not multipart, it's a single plain text message
        body = email_message.get_payload(decode=True).decode()

    # Body pre-processing
    urls_list = []
    if body.find("Content-Transfer-Encoding: quoted-printable") != -1:
        print ("Quoted-printable content")
        decoded_bytes_object = quopri.decodestring(body)
        body = decoded_bytes_object.decode("utf-8", errors="ignore")  # TODO: get the right charset
        soup = BeautifulSoup(body, 'html.parser')

        # we try to find URLS in the href attribute of a, img, and div tags
        for a_tag in soup.find_all(re.compile('a|img|div', re.I)):
            href = a_tag.get("href")
            if href != None:
              if href.startswith('tel') or href.startswith('sms'):
                metatag = "PHONE"
                href = href.replace(r'(tel|sms):', '')
              elif href.startswith('mailto'):
                metatag = "EMAIL"
                href = href.replace('mailto:', '')
              else:
                metatag = "URL"
                urls_list.append(href)
              visible_string = a_tag.string or ""
              a_tag.replace_with(f'[{metatag} HREF="{href}"] {visible_string} [/{metatag}]')

        body = soup.get_text()
        # get the initial URL part only [protocol+FQDN(fully qualified domain name)] \g<1> = protocol (+ www.), \g<2> = FQDN
        body = re.sub(
            r"(https?:\/\/|www\.)([-a-zA-Z0-9@:%._\-\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6})\b[-a-zA-Z0-9()@:%_+.~#?&\/=\-]*",
            r"\g<1>\g<2>", body)

        body = re.sub(r" {2,}", " ", body)  # remove duplicate blanks
        body = re.sub(r"\n{2,}", "\n", body) # remove duplicate \n chars
        #body = urllib.parse.parseqsl(body)
        #body = body.replace(r'=[0-9A-F]{2}', '')

    return {
      "headers": headers,
      "subject" : subject,
      "body" : body,
      "urls" : urls_list
    }