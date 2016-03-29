from pyvirtualdisplay import Display
from selenium import webdriver
import time

import sys

website = sys.argv[1]
tempo = int(sys.argv[2])

display = Display(visible=0, size=(800, 600))
display.start()

browser = webdriver.Firefox()
browser.get(website)
print "Start capturing %s for %d" % (website, tempo)

time.sleep(tempo)
browser.quit()

display.stop()
