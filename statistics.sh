#!/bin/sh
clear
echo "//==========Today====================================="
echo "code summary infomation:"
find . -name "*.java" -mtime 0 | xargs cat | grep -v ^$ | wc -l 
echo "documents summary infomation:"
find . -name "*.md" -mtime 0 | xargs cat | grep -v ^$ | wc -l 
echo ""

echo "//==========This Week================================="
echo "code summary infomation:"
find . -name "*.java" -mtime -7| xargs cat | grep -v ^$ | wc -l 
echo "documents summary infomation:"
find . -name "*.md" -mtime -7| xargs cat | grep -v ^$ | wc -l 
git log --pretty=format:"%h - %an,%ci: %s " | grep  `date +%F --date="-0 days"`
git log --pretty=format:"%h - %an,%ci: %s " | grep  `date +%F --date="-1 days"`
git log --pretty=format:"%h - %an,%ci: %s " | grep  `date +%F --date="-2 days"`
git log --pretty=format:"%h - %an,%ci: %s " | grep  `date +%F --date="-3 days"`
git log --pretty=format:"%h - %an,%ci: %s " | grep  `date +%F --date="-4 days"`
git log --pretty=format:"%h - %an,%ci: %s " | grep  `date +%F --date="-5 days"`
git log --pretty=format:"%h - %an,%ci: %s " | grep  `date +%F --date="-6 days"`
echo ""
echo ""

echo "//==========All================================="
echo "code summary infomation:"
find . -name "*.java"| xargs cat | grep -v ^$ | wc -l 
echo "documents summary infomation:"
find . -name "*.md"| xargs cat | grep -v ^$ | wc -l 
echo "commit history:"
git log --pretty=format:"%h - %an,%ci: %s "


