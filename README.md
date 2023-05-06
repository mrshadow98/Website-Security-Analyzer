
# Website Security Analyzer

Website Security Analyzer is an Web app designed to help users analyze the security of websites and protect themselves from potential threats such as phishing attempts, malware downloads, and man-in-the-middle attacks.

The app provides a variety of features to help users assess the safety of websites they visit, including URL analysis, DGA score calculation, machine learning-based phishing probability detection, hidden element detection, suspicious cookie analysis, connected domain/subdomain analysis, and technology detection. The app also checks blacklists, performs GeoIP lookups, validates SSL certificates, analyzes website content, checks reputations, performs WHOIS lookups, checks social media presence, performs domain name typo checks, validates email addresses, Gathers all subdomains, urls present in the page and analyzes password strength.

This app, also work as stand-alone python script to perform OSCINT or Information Gathering purpose for security professionals or penetration tester or Bug Bounty Hunters

## Installation

Project is tested on python 3.8 and golang:1.20.4.
Also supports docker for Installation.
For manual setup follow the guide.

```bash

git clone https://github.com/mrshadow98/Website-Security-Analyzer.git

pip install --upgrade pip setuptools
pip install -r req.txt
pip install cython
pip install numpy==1.23.5
python -m pip install --upgrade Pillow
pip install geoip2==4.6.0
pip install selenium==4.9.0
pip install ipwhois==1.2.0

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

## Usage/Examples

For Script
```bash

python .\Analyser\analyzer.py -url https://geniobits.com 
python .\Analyser\analyzer.py -file file.txt

optional arguments:                                                                               
  -h, --help            show this help message and exit                                           
  -url URL              URL to test                                                               
  -file FILE            local file to load data from                                              
  -vtk VTK              Virus Total Key                                                           
  -gsbk GSBK            Google safe browsing key                                                  
  -output_file FILE     file to write output data to

```

For Docker
```docker
docker-compose up --build

```
Visit localhost:5050/admin



## Contributing

Contributions are always welcome!

Contributions to the project are welcome. If you have an idea for a new feature, or would like to improve an existing feature, please create a pull request with your changes. Before submitting a pull request, please ensure your changes are thoroughly tested and documented.




## License

[MIT](https://choosealicense.com/licenses/mit/)

This project is licensed under the MIT License - see the LICENSE file for details.
