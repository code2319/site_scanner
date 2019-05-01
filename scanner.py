import io
import os
import sys
import json
import socket
import warnings
import platform
from urllib.request import Request, urlopen
from ipwhois import IPWhois
from tld import get_tld
from fake_useragent import UserAgent


def get_ip_by_url(url):
    try:
        domain_name = get_tld(url, as_object=True)
        ip = socket.gethostbyname(domain_name.fld)
        return ip
    except:
        print("Ошибка в адресе сайта.")
        sys.exit()


def get_robots_txt(url):
    if url.endswith('/'):
        path = url
    else:
        path = url + "/"

    ua = UserAgent()
    rp = Request(path + "robots.txt", headers={'User-Agent': str(ua.random)})
    rp = urlopen(rp, data=None)
    data = io.TextIOWrapper(rp, encoding='utf-8')
    with open("robots.txt", 'tw') as f:
        f.write(data.read())
    f.close()


def check_ports(ip):
    if platform.system() == "Linux":
        try:
            command = "nmap -F " + ip
            ps = os.popen(command)
            res = str(ps.read())
            with open("nmap.txt", "tw") as f1:
                f1.write(res)
                f1.close()
        except Exception as err:
            print(err)


def get_whois(ip, fname):
    obj = IPWhois(ip)
    with warnings.catch_warnings():
        warnings.filterwarnings(action="ignore", category=UserWarning)
        res = obj.lookup_rdap(depth=1)
    with open(fname, 'tw') as f:
        f.write(json.dumps(res))
    f.close()


def analyze_json(fname):
    try:
        with open(fname, 'r') as f, open("res.txt", 'tw') as f2:
            data = json.load(f)
            asn = "asn_registry: " + data["asn_registry"] + \
                  "\nasn: " + data["asn"] + \
                  "\nasn_cidr: " + data["asn_cidr"] + \
                  "\nasn_country_code: " + data["asn_country_code"] + \
                  "\nnetwork: " + data["network"]["handle"] + \
                  "\nnetwork: " + data["network"]["start_address"] + " - " + data["network"]["end_address"] + "\n\n"
            f2.write(asn)

            for i in data["objects"]:
                n = data["objects"][i]["contact"]["name"]

                addr = data["objects"][i]["contact"]["address"]
                if addr:
                    addr = json.dumps(data["objects"][i]["contact"]["address"][0]["value"]).replace("\\n", ", ")

                ph = data["objects"][i]["contact"]["phone"]
                if ph:
                    ph = data["objects"][i]["contact"]["phone"][0]["value"]

                e = data["objects"][i]["contact"]["email"]
                if e:
                    e = data["objects"][i]["contact"]["email"][0]["value"]

                res = i + "\nName: " + n + "\nAddress: " + addr + "\nPhone: " + str(ph) + "\nEmail: " + str(e) + "\n\n"
                f2.write(res)
    except Exception as err:
        print(err)


if __name__ == "__main__":
    jfname = "whois.json"
    url = input("Введите адрес сайта (например: https://pypi.org/): ")
    site_ip = (get_ip_by_url(url))
    get_robots_txt(url)
    check_ports(site_ip)
    get_whois(site_ip, jfname)
    analyze_json(jfname)