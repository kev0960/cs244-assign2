# Measuring ICW

## How To Start


1. Run `sudo bash ./setup.sh (Number of Ports to use)`
E.g `sudo bash ./setup.sh 10`

2. Specify the name of websites to use at top.txt
3. `sudo python2 main.py --numwebsite=(Number of Websites) --numport=(Number of ports)`
E.g `sudo python2 main.py --numwebsite=5000 --numport=10`

4. Result will be written in table_2.txt, table_3.txt and table_4.txt
table_2.txt contains the category info. table_3 contains the websites and its corresponding MSS size.
table_4.txt contains more detailed info. The Figure 1 in the paper was generated using parser.py with table_4.txt
