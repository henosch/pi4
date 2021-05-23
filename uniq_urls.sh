#!/usr/bin/bash
# Check all lists for unique ones and show the percentage

[ "$UID" -eq 0  ] || exec sudo bash "$0" "$@"

cd /etc/pihole/
cat *.domains | sort | uniq -u > all_adlist_urls_sorted_unique.txt

# Result
T1=$(cat *.domains | wc -l)
T2=$(cat all_adlist_urls_sorted_unique.txt | wc -l)
S=$(python -c "p = $T2 / $T1 * 100; print(p)")
printf "URLs total:		%10d\n" $T1
printf "URLs unique:	%10d\n" $T2
printf "Percentage:	  %8.1f %%\n" $S
