import whois
import requests
import dns.resolver
from threading import Thread, Lock
from queue import Queue

q = Queue()
list_lock = Lock()
discovered_subdomains = []


def is_registered(domain_name):
    """
    A function that returns a boolean indicating
    whether a `domain_name` is registered
    """

    try:
        w = whois.whois(domain_name)
    except Exception:
        return False
    else:
        return bool(w.domain_name)


def resolve_dns_records(target_domain):
    """A function that resolves DNS records for a `target_domain`"""
    # List of record types to resolve

    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]

    # Create a DNS resolver
    resolver = dns.resolver.Resolver()

    for record_type in record_types:
        try:
            answers = resolver.resolve(target_domain, record_type)
        except Exception:
            continue

        # Print the DNS records found

        print(f"DNS records for {target_domain} ({record_type}):")
        for rdata in answers:
            print(rdata)


def get_subdomains(domain):
    # a list of the discovered subdomains
    global q
    while True:
        # get the subdomain from the queue

        subdomain = q.get()
        url = f"http://{subdomain}.{domain}"

        try:
            requests.get(url)
        except Exception as e:
            pass
        else:
            print("[+] discovered subdomain: ", url)

            with list_lock:
                discovered_subdomains.append(url)
        q.task_done()


def main(domain, n_threads, subdomains):
    global q

    for sub_domain in subdomains:
        q.put(sub_domain)

    for t in range(n_threads):
        # start all threads
        worker = Thread(target=get_subdomains, args=(domain, ))
        worker.daemon = True
        worker.start()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Domain name information extractor "
                                                 "which uses WHOIS database and scans for subdomain names")

    parser.add_argument("domain", help="The domain name without http(s)")
    parser.add_argument("-t", "--timeout", type=int, default=2,
                        help="The timout in seconds for prompting the connection, default is 2")
    parser.add_argument("-s", "--subdomains", default="subdomains.txt",
                        help="The file path that contains the list of subdomains to scan, default is subdomains.txt")
    parser.add_argument("-n", "--num-threads", help="Number of threads to use to scan the domain. Default is 10",
                        default=10, type=int)
    parser.add_argument("-o", "--output-file", help="The output file path resulting the discovered subdomains")

    args = parser.parse_args()

    if is_registered(args.domain):
        whois_info = whois.whois(args.domain)
        # print the registrar
        print("Domain registrar: ", whois_info.registrar)
        print("WHOIS server: ", whois_info.whois_server)
        print("Domain creation date: ", whois_info.creation_date)
        print("Domain expiration date: ", whois_info.expiration_date)
        print(whois_info)

    print("=" * 50, "DNS records", "=" * 50)
    resolve_dns_records(args.domain)
    print("=" * 50, "Scanning subdomains", "=" * 50)

    domain = args.domain
    wordlist = args.subdomains
    num_threads = args.num_threads
    output_file = args.output_file

    main(domain=domain, n_threads=num_threads, subdomains=open(wordlist).read().splitlines())
    q.join()
    # save the discovered subdomains into a file
    with (open(output_file, "w")) as f:
        for url in discovered_subdomains:
            print(url, file=f)
