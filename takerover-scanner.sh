#!/bin/bash

# Subdomain Enumeration and JS Analysis Script

# Check if required tools are installed
check_requirements() {
    echo "[+] Checking requirements..."
    
    command -v subfinder >/dev/null 2>&1 || { echo "[-] Error: subfinder is not installed. Please install it first."; exit 1; }
    command -v amass >/dev/null 2>&1 || { echo "[-] Error: amass is not installed. Please install it first."; exit 1; }
    command -v curl >/dev/null 2>&1 || { echo "[-] Error: curl is not installed. Please install it first."; exit 1; }
    command -v jq >/dev/null 2>&1 || { echo "[-] Error: jq is not installed. Please install it first."; exit 1; }
    command -v grep >/dev/null 2>&1 || { echo "[-] Error: grep is not installed. Please install it first."; exit 1; }

    echo "[+] All required tools are installed."
}

# Parse command line arguments
parse_args() {
    if [ $# -lt 1 ]; then
        echo "Usage: $0 <domain> [output_directory]"
        echo "Example: $0 example.com results"
        exit 1
    fi

    DOMAIN=$1
    
    if [ -z "$2" ]; then
        OUTPUT_DIR="$(pwd)/subdomain_scan_$(date +%Y%m%d_%H%M%S)"
    else
        OUTPUT_DIR="$(pwd)/$2"
    fi
    
    mkdir -p "$OUTPUT_DIR"
    echo "[+] Output will be saved to: $OUTPUT_DIR"
}

# Run subfinder to discover subdomains
run_subfinder() {
    echo "[+] Running subfinder on $DOMAIN..."
    subfinder -d "$DOMAIN" -o "$OUTPUT_DIR/subfinder_results.txt"
    echo "[+] Subfinder completed. Results saved to $OUTPUT_DIR/subfinder_results.txt"
}

# Run amass to discover additional subdomains
run_amass() {
    echo "[+] Running amass on $DOMAIN..."
    amass enum -d "$DOMAIN" -o "$OUTPUT_DIR/amass_results.txt"
    echo "[+] Amass completed. Results saved to $OUTPUT_DIR/amass_results.txt"
}

# Combine and deduplicate results
combine_results() {
    echo "[+] Combining and deduplicating results..."
    cat "$OUTPUT_DIR/subfinder_results.txt" "$OUTPUT_DIR/amass_results.txt" | sort -u > "$OUTPUT_DIR/all_subdomains.txt"
    echo "[+] Found $(wc -l < "$OUTPUT_DIR/all_subdomains.txt") unique subdomains."
}

# Check if subdomains are live
check_live_subdomains() {
    echo "[+] Checking which subdomains are live..."
    
    > "$OUTPUT_DIR/live_subdomains.txt"
    
    while read subdomain; do
        if curl -s --connect-timeout 5 --max-time 10 -o /dev/null -I -w "%{http_code}" "https://$subdomain" | grep -q -E "^[23]"; then
            echo "$subdomain" >> "$OUTPUT_DIR/live_subdomains.txt"
            echo "    [+] $subdomain is live"
        elif curl -s --connect-timeout 5 --max-time 10 -o /dev/null -I -w "%{http_code}" "http://$subdomain" | grep -q -E "^[23]"; then
            echo "$subdomain" >> "$OUTPUT_DIR/live_subdomains.txt"
            echo "    [+] $subdomain is live"
        else
            echo "    [-] $subdomain is not responding"
        fi
    done < "$OUTPUT_DIR/all_subdomains.txt"
    
    echo "[+] Found $(wc -l < "$OUTPUT_DIR/live_subdomains.txt") live subdomains."
}

# Find JavaScript files from subdomains
find_js_files() {
    echo "[+] Finding JavaScript files from live subdomains..."
    
    > "$OUTPUT_DIR/js_files.txt"
    
    while read subdomain; do
        echo "    [+] Searching for JS files on $subdomain..."
        
        # Try HTTPS first, then HTTP if HTTPS fails
        if ! curl -s -L --connect-timeout 5 --max-time 20 "https://$subdomain" > "$OUTPUT_DIR/temp.html"; then
            curl -s -L --connect-timeout 5 --max-time 20 "http://$subdomain" > "$OUTPUT_DIR/temp.html"
        fi
        
        # Extract JS file references
        grep -o -E 'src="[^"]*\.js"' "$OUTPUT_DIR/temp.html" | sed 's/src="//;s/"$//' >> "$OUTPUT_DIR/raw_js_paths.txt"
        grep -o -E "src='[^']*\.js'" "$OUTPUT_DIR/temp.html" | sed "s/src='//;s/'$//" >> "$OUTPUT_DIR/raw_js_paths.txt"
        
        # Process JS paths to get full URLs
        while read js_path; do
            if [[ "$js_path" == http* ]]; then
                # Already a full URL
                echo "$js_path" >> "$OUTPUT_DIR/js_files.txt"
            elif [[ "$js_path" == //* ]]; then
                # Protocol-relative URL
                echo "https:$js_path" >> "$OUTPUT_DIR/js_files.txt"
            elif [[ "$js_path" == /* ]]; then
                # Absolute path
                echo "https://$subdomain$js_path" >> "$OUTPUT_DIR/js_files.txt"
            else
                # Relative path
                echo "https://$subdomain/$js_path" >> "$OUTPUT_DIR/js_files.txt"
            fi
        done < "$OUTPUT_DIR/raw_js_paths.txt"
        
        > "$OUTPUT_DIR/raw_js_paths.txt"
    done < "$OUTPUT_DIR/live_subdomains.txt"
    
    # Deduplicate
    sort -u "$OUTPUT_DIR/js_files.txt" -o "$OUTPUT_DIR/js_files.txt"
    echo "[+] Found $(wc -l < "$OUTPUT_DIR/js_files.txt") JavaScript files."
}

# Analyze JS files for AWS/S3 references
analyze_js_files() {
    echo "[+] Analyzing JavaScript files for AWS/S3 references..."
    
    > "$OUTPUT_DIR/js_analysis_results.txt"
    
    echo "============================================================" >> "$OUTPUT_DIR/js_analysis_results.txt"
    echo "JS FILES WITH POTENTIAL AWS/S3 REFERENCES" >> "$OUTPUT_DIR/js_analysis_results.txt"
    echo "============================================================" >> "$OUTPUT_DIR/js_analysis_results.txt"
    
    while read js_url; do
        echo "    [+] Analyzing $js_url..."
        
        # Download the JS file
        js_content=$(curl -s -L --connect-timeout 5 --max-time 10 "$js_url")
        
        # Search for AWS/S3 references
        if echo "$js_content" | grep -i -E "aws|amazon|s3|bucket|amazonaws.com" > /dev/null; then
            echo "$js_url" >> "$OUTPUT_DIR/js_analysis_results.txt"
            echo "------------------------------------------------------------" >> "$OUTPUT_DIR/js_analysis_results.txt"
            
            # Extract specific patterns
            echo "AWS REFERENCES:" >> "$OUTPUT_DIR/js_analysis_results.txt"
            echo "$js_content" | grep -i -A 2 -B 2 "aws" >> "$OUTPUT_DIR/js_analysis_results.txt"
            echo "" >> "$OUTPUT_DIR/js_analysis_results.txt"
            
            echo "S3 REFERENCES:" >> "$OUTPUT_DIR/js_analysis_results.txt"
            echo "$js_content" | grep -i -A 2 -B 2 "s3" >> "$OUTPUT_DIR/js_analysis_results.txt"
            echo "" >> "$OUTPUT_DIR/js_analysis_results.txt"
            
            echo "AMAZONAWS.COM REFERENCES:" >> "$OUTPUT_DIR/js_analysis_results.txt"
            echo "$js_content" | grep -i -A 2 -B 2 "amazonaws.com" >> "$OUTPUT_DIR/js_analysis_results.txt"
            echo "" >> "$OUTPUT_DIR/js_analysis_results.txt"
            
            echo "BUCKET REFERENCES:" >> "$OUTPUT_DIR/js_analysis_results.txt"
            echo "$js_content" | grep -i -A 2 -B 2 "bucket" >> "$OUTPUT_DIR/js_analysis_results.txt"
            echo "" >> "$OUTPUT_DIR/js_analysis_results.txt"
            
            echo "============================================================" >> "$OUTPUT_DIR/js_analysis_results.txt"
            echo "" >> "$OUTPUT_DIR/js_analysis_results.txt"
            
            echo "    [!] Found potential AWS/S3 references in $js_url"
        fi
    done < "$OUTPUT_DIR/js_files.txt"
    
    echo "[+] Analysis completed. Results saved to $OUTPUT_DIR/js_analysis_results.txt"
}

# Generate report
generate_report() {
    echo "[+] Generating final report..."
    
    cat > "$OUTPUT_DIR/report.md" << EOL
# Subdomain Takeover Vulnerability Scan Report

## Overview
- **Target Domain:** $DOMAIN
- **Scan Date:** $(date)
- **Total Subdomains Found:** $(wc -l < "$OUTPUT_DIR/all_subdomains.txt")
- **Live Subdomains:** $(wc -l < "$OUTPUT_DIR/live_subdomains.txt")
- **JavaScript Files Found:** $(wc -l < "$OUTPUT_DIR/js_files.txt")

## Potential Subdomain Takeover Vulnerabilities

The following JavaScript files contain references to AWS/S3 which might indicate potential subdomain takeover vulnerabilities:

EOL

    # Check if any findings were recorded
    if grep -q "aws\|s3\|amazonaws.com\|bucket" "$OUTPUT_DIR/js_analysis_results.txt"; then
        # Extract URLs of JS files with findings
        grep -v "^AWS\|^S3\|^AMAZONAWS\|^BUCKET\|^--\|^==" "$OUTPUT_DIR/js_analysis_results.txt" | grep "http" >> "$OUTPUT_DIR/report.md"
        
        echo -e "\n## Next Steps\n\n1. Verify if any of these resources are no longer controlled by your organization\n2. Check if the S3 buckets or AWS resources referenced are properly configured\n3. Claim any unclaimed resources to prevent subdomain takeover attacks" >> "$OUTPUT_DIR/report.md"
    else
        echo -e "\nNo potential subdomain takeover vulnerabilities were found in the JavaScript files." >> "$OUTPUT_DIR/report.md"
    fi
    
    echo "[+] Report generated: $OUTPUT_DIR/report.md"
}

# Clean up temporary files
cleanup() {
    echo "[+] Cleaning up temporary files..."
    rm -f "$OUTPUT_DIR/temp.html" "$OUTPUT_DIR/raw_js_paths.txt"
    echo "[+] Done!"
}

# Main execution
main() {
    echo "=========================================================="
    echo "   Subdomain Enumeration and JS Analysis for Takeover     "
    echo "=========================================================="
    
    check_requirements
    parse_args "$@"
    
    run_subfinder
    run_amass
    combine_results
    check_live_subdomains
    find_js_files
    analyze_js_files
    generate_report
    cleanup
    
    echo "=========================================================="
    echo "                       Scan Complete                      "
    echo "=========================================================="
    echo "Results are available in: $OUTPUT_DIR"
    echo "Summary report: $OUTPUT_DIR/report.md"
}

# Execute
main "$@"
