#Retreives the top 500 Alexa sites put it in single .list file

#!/bin/bash
for item in {0..19};do curl -o alexa_global.$item "http://www.alexa.com/topsites/global;$item" && grep "\<a href\=\"\/siteinfo\/" alexa_global.$item | awk -F">" '{print $7}' | cut -d"<" -f1 >> alexa_top500.list && rm -r alexa_global.$item;done
