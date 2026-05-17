import re

def extract_subdomains(input_file, output_file):
    """
    Extracts subdomains from a file and writes them to another file.

    :param input_file: Path to the input file containing URLs/domains.
    :param output_file: Path to the output file for extracted subdomains.
    """
    # Regular expression to match subdomains
    subdomain_pattern = r"(?<!www\.)\b(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}\b"
    
    subdomains = set()  # Use a set to avoid duplicates

    try:
        # Read the input file
        with open(input_file, 'r') as file:
            for line in file:
                matches = re.findall(subdomain_pattern, line.strip())
                subdomains.update(matches)
        
        # Write the extracted subdomains to the output file
        with open(output_file, 'w') as file:
            for subdomain in sorted(subdomains):
                file.write(subdomain + '\n')
        
        print(f"Subdomains have been extracted and saved to {output_file}")
    
    except FileNotFoundError:
        print(f"Error: File {input_file} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example usage
input_file = "domains.txt"  # Replace with your input file name
output_file = "subdomains.txt"  # Replace with your desired output file name

extract_subdomains(input_file, output_file)
