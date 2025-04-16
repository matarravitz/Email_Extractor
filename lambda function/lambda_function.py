import boto3
import re
from typing import Dict, Any, Set, List
import validators
import json
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import asyncio
from aiohttp import ClientSession, ClientTimeout

# setting the dataBase info
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Domain-to-emails')


def lambda_response(response_dict: Dict, status_code: int = 200) -> Dict:
    """
    Raise the appropriate message - error or success.

    Args:
        response_dict (Dict): Dictionary that contains the response's details.
        status_code (int): HTTP status code. Defaults to 200 - success.

    Returns:
        Dict: Dictionary formatted as an HTTP Lambda response object with CORS headers.
    """
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
    """
    Extract all valid email addresses from a given HTML source.

    Args:
        url_response (str): The HTML content to extract emails from.

    Returns:
        Set[str]: A set of unique and valid email addresses that was found.
    """
    emails = set()
    match_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', url_response)
    # Using regex to find all strings that match the email pattern.
    for mail in match_emails:
        if validators.email(mail):
            emails.add(mail)
    # if the mail is valid, add it to the list
    return emails


def url_extractor(url_response: str, url: str) -> Set[str]:
    """
    Extract all valid url addresses from an HTML source.

    Args:
        url_response (str): The HTML content to extract Urls from.
        url (str): The base URL for the search and extraction process.

    Returns:
        Set[str]: A set of unique and valid url addresses that was found.
    """
    urls = set()
    soup = BeautifulSoup(url_response, "html.parser")
    links = soup.find_all('a', href=True) # finds all the lines in the HTML content that mark with <a> tag and not umpty.
    domain = urlparse(url).netloc # extracts the url's domain
    for link in links:
        href = link['href'] # extract the href attribute from an HTML tag.
        extracted_url = urljoin(url, href)
        if validators.url(extracted_url) and urlparse(extracted_url).netloc == domain:
            if extracted_url != url and extracted_url != url + "/" and \
            "#" not in extracted_url and extracted_url not in urls:
                #The check for "#" is included because URLs containing the # character are often reference a specific section within the same page, rather than a separate page.
                urls.add(extracted_url)
        # Ensures that the links added valid and belong to the same domain as the given URL.  
        # Ensures that the links added are uniqe.
    return urls


async def web_scanner(url: str, session: ClientSession, num_of_round: int) -> Dict[str, Set[str]]:
    """
    An asynchronous function that extracts valid URL and email addresses from an HTML source.

    Args:
        url (str): The base URL for the search and extraction process.
        session (ClientSession): A shared HTTP client session used for making requests efficiently across multiple scans.
        num_of_round (int): The current round number of the scan - can be 1 or 2.

    Returns:
        Dict[str, Set[str]]: A dictionary containing sets of unique and valid URLs and email addresses found.
    """
    urls = set()
    async with session.get(url) as response:
        response = await response.text()
    # get the source code.
    emails = email_extractor(response)
    if num_of_round == 1: # if it's the first round, starting a second acan
        urls = url_extractor(response, url)
    # extracting all the emails and urls from the source code.
    return {"url": url, "emails": emails, "paths": urls}


def cache_emails(scan_results: List[Dict]) -> None:
    """
    Saves the extracted emails and URLs from the base URL in the dynamoDB table for faster extraction in the future.

    Args:
        scan_results (List[Dict]): A list of dictionaries containing the extracted emails and URLs to be cached.
    """
    
    for i in range(0, len(scan_results), 100): #making chankes of size 100 
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
                if url in urls: # if there is already the same url
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
        found_items = response.get('Responses', {}).get('Domain-to-emails', []) ###
        results.update({item['URL']: item for item in found_items})
    return results


async def controller(url: str, session: ClientSession, response_dynamo, num_of_round: int) -> Dict:
    """
    Controls the scanning of email addresses and URLs for a given base URL.
    This function checks if the given URL is cached in the DynamoDB response. If cached, it retrieves the data
    from the cache. Otherwise, it performs a scan of the URL using `web_scanner`, saves the results, and returns them.
    It also handles timeout errors based on the scan round.

    Args:
        url (str): The base URL for the search and extraction process.
        session (ClientSession): A shared HTTP client session for multiple scans.
        response_dynamo (dict): A dictionary containing cached results for previously scanned URLs.
        num_of_round (int): The current scan round number, used to determine retry logic.
    
    Returns:
        Dict: A dictionary containing the URL, email addresses, and paths.

    Raises:
        TimeoutError: Raised if a timeout occurs during the first round of scanning.
    """
    try:
        if url not in response_dynamo:
            # If the URL is not found in the cache, perform a scan using the web_scanner function
            # and save the scanned data in the database.
            result = await web_scanner(url, session, num_of_round)

        else:
            # If the URL is already scanned and cached, retrieve the data from the cache.
            result = {
                "url": url,
                "emails": response_dynamo[url]['email_list'],
                "paths": response_dynamo[url]['path_list']
            }
        return result

    except TimeoutError :
        if num_of_round == 1:
            # If a timeout occurs during the first scan round, raise a TimeoutError
            raise TimeoutError
        if num_of_round == 2:
            #  If a timeout occurs during the second scan round, return an empty dictionary instead of raising an error.
            return dict()


async def main(event, context) -> Dict[str, Any]:
    """
    The main function that starting the URL scanning process, extracting emails from 
    the provided domain and from the URL's in his source code. Also caches the results.

    Parameters:
    event (Dict): Event object that contains query parameters, including the target domain URL.
                  Expected format: {"queryStringParameters": {"domain": "<URL>"}}
    context (Any): AWS Lambda context object providing runtime information about the invocation.

    Returns:
    Dict[str, Any]: A dictionary containing the following keys:
        - "emails": A list of extracted unique email addresses.
        - "urls": A list of extracted unique URLs.
        - OR an error response if any issues occur.
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

        #if results:
        results.append(result)
        results = [result for result in results if result]
        for result in results:
            valid_emails = valid_emails.union(result["emails"])
        #if results:
        cache_emails(results)
        urls_list = []
        for result in results:
            urls_list.extend(result["paths"])


    except Exception:
        e = traceback.format_exc()
        return lambda_response({'error': e}, 500)
        # If an error occurs, return a generic error message.

    return lambda_response(
        {"emails": list(valid_emails),
         "urls": list(set(urls_list))})  # Returns a dictionary containing a list of emails in the body.


def lambda_handler(event, context) -> Dict[str, Any]:
    # Wrapper Function (lambda can't be asynchronous)
    return asyncio.run(main(event, context))
