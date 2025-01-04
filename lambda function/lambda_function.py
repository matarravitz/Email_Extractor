import boto3
import re
from typing import Dict, Any, Set, List
import validators
import json
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import traceback
import asyncio
from aiohttp import ClientSession, ClientTimeout

# setting the dataBase info
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Domain-to-emails')


def lambda_response(response_dict: Dict, status_code: int = 200) -> Dict:
    # raise the appropriate error message
    return {
        "isBase64Encoded": False,
        "statusCode": status_code,
        "headers": {
            "Access-Control-Allow-Origin": "https://emailextractorbucket.s3.eu-north-1.amazonaws.com",
            "Access-Control-Allow-Methods": "GET,OPTIONS"
        },
        "body": json.dumps(response_dict)
    }


def email_extractor(url_response: str) -> Set[str]:
    emails = set()
    match_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', url_response)
    # Using regex to find all strings that match the email pattern.
    for mail in match_emails:
        if validators.email(mail):
            emails.add(mail)
    # if the mail is valid, add it to the list
    return emails


def url_extractor(url_response: str, url: str) -> Set[str]:
    urls = set()
    soup = BeautifulSoup(url_response, "html.parser")
    links = soup.find_all('a', href=True)
    domain = urlparse(url).netloc
    for link in links:
        href = link['href']
        extracted_url = urljoin(url, href)
        if validators.url(extracted_url) and urlparse(extracted_url).netloc == domain:
            if extracted_url != url and extracted_url != url + "/" and \
            "#" not in extracted_url and extracted_url not in urls:
                urls.add(extracted_url)
        #if len(urls) >= 50:
            #break
    return urls


async def web_scanner(url: str, session: ClientSession, num_of_round) -> Dict:
    urls = set()
    async with session.get(url) as response:
        response = await response.text()
    # get the source code.
    emails = email_extractor(response)
    if num_of_round == 1:
        urls = url_extractor(response, url)
    # extracting all the emails and urls from the source code.
    return {"url": url, "emails": emails, "paths": urls}


def cache_emails(scan_results: List[Dict]) -> None:
    # entering data to the dynamoDB table.
    for i in range(0, len(scan_results), 100):
        if len(scan_results) - i >= 100:
            chunk = scan_results[i:i + 100]
        else:
            chunk = scan_results[i:]
        if not chunk:  # Skip empty chunks
            continue
        urls = []
        with table.batch_writer() as batch:
            for result in chunk:
                url = result['url']
                if url in urls:
                    continue
                urls.append(url)
                email_list = result["emails"]
                path_list = result["paths"]
                batch.put_item(Item={
                    'URL': url,
                    'email_list': list(email_list),
                    'path_list': list(path_list),
                    'expirationTime': int(time.time()) + 3600  # will be deleted 1 hour from now.
                })


def get_cache(urls: Set[str]) -> Dict:
    results = {}
    urls = list(urls)
    for i in range(0, len(urls), 100):
        if len(urls) - i >= 100:
            chunk = urls[i:i + 100]
        else:
            chunk = urls[i:]
        if not chunk:  # Skip empty chunks
            continue
        urls = [{"URL": url} for url in chunk]
        response = dynamodb.batch_get_item(
            RequestItems={
                'Domain-to-emails': {
                    'Keys': urls
                }
            }
        )
        found_items = response.get('Responses', {}).get('Domain-to-emails', [])
        results.update({item['URL']: item for item in found_items})
    return results


async def controller(url: str, session: ClientSession, response_dynamo, num_of_round) -> Dict:
    try:
        if url not in response_dynamo:
            # if not in cache, scan it, and save the data in the database.
            result = await web_scanner(url, session, num_of_round)

        else:
            result = {
                "url": url,
                "emails": response_dynamo[url]['email_list'],
                "paths": response_dynamo[url]['path_list']
            }
            # if the url were scanned, using the saved data.
        return result

    except TimeoutError :
        if num_of_round == 1:
            raise TimeoutError
        if num_of_round == 2:
            return dict()


async def main(event, context) -> Dict[str, Any]:
    """
    Extracts all email addresses from a web page.

    Parameters:
    event (Dict): Dictionary containing the submitted URL.

    Returns:
    Dict: Dictionary containing the extracted emails or an error message.
    """
    valid_emails = set()
    try:
        url = event['queryStringParameters']['domain']
        if not validators.url(url):
            return lambda_response({"error": "Invalid URL"}, 500)
        dynamodb_response = get_cache(set(url))
        timeout = ClientTimeout(10)
        async with ClientSession(timeout=timeout) as session:
            try:
                result = await controller(url, session, dynamodb_response, 1)
            except TimeoutError:
                return lambda_response({"error": "An error occurred while trying to access the URL."}, 500)
            # starting a second scan.
            urls = {found_url for found_url in result["paths"]}
            dynamodb_response = get_cache(urls)
            tasks = [controller(found_url, session, dynamodb_response, 2) for found_url in urls]
            results: List = await asyncio.gather(*tasks)  # type: ignore

        if results:
            results.append(result)
        results = [result for result in results if result]
        for result in results:
            valid_emails = valid_emails.union(result["emails"])
        cache_emails(result)
        urls_list = []
        for result in results:
            urls_list.extend(result["paths"])


    except Exception:
        e = traceback.format_exc()
        return lambda_response({'error': e}, 500)
        #return lambda_response({"error": "An error occurred while trying to access the URL."}, 500)
        # If an error occurs, return a generic error message.

    return lambda_response(
        {"emails": list(valid_emails),
         "urls": list(set(urls_list)),
         "url_len": len(set(urls_list))})  # Returns a dictionary containing a list of emails in the body.


def lambda_handler(event, context) -> Dict[str, Any]:
    return asyncio.run(main(event, context))


# Success :)