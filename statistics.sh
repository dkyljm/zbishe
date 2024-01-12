#!/bin/sh
clear

target_folder="/home/ljm/zBESHELJP/zbishe"  # 替换成你的目标文件夹路径

echo "//==========Today====================================="
echo "code summary information:"
find "$target_folder" -name "*.c" -mtime 0 | xargs cat | grep -v ^$ | wc -l
echo ""

echo "//==========This Week================================="
echo "code summary information:"
find "$target_folder" -name "*.c" -mtime -7 | xargs cat | grep -v ^$ | wc -l
git log --pretty=format:"%h - %an,%ci: %s " -- "$target_folder" | grep  `date +%F --date="-0 days"`
git log --pretty=format:"%h - %an,%ci: %s " -- "$target_folder" | grep  `date +%F --date="-1 days"`
git log --pretty=format:"%h - %an,%ci: %s " -- "$target_folder" | grep  `date +%F --date="-2 days"`
git log --pretty=format:"%h - %an,%ci: %s " -- "$target_folder" | grep  `date +%F --date="-3 days"`
git log --pretty=format:"%h - %an,%ci: %s " -- "$target_folder" | grep  `date +%F --date="-4 days"`
git log --pretty=format:"%h - %an,%ci: %s " -- "$target_folder" | grep  `date +%F --date="-5 days"`
git log --pretty=format:"%h - %an,%ci: %s " -- "$target_folder" | grep  `date +%F --date="-6 days"`
echo ""
echo ""

echo "//==========All================================="
echo "code summary information:"
find "$target_folder" -name "*.c" | xargs cat | grep -v ^$ | wc -l
echo "commit history:"
git log --pretty=format:"%h - %an,%ci: %s " -- "$target_folder"

