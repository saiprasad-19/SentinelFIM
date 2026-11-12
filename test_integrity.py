
from core.integrity import calculate_hash

# Create a sample file
with open("sample.txt", "w") as file:
    file.write("SentinelFIM security test")

# Calculate its SHA-256 hash
result = calculate_hash("sample.txt")

print("File SHA-256 Hash:")
print(result)

if result:
    print("\nSUCCESS: File integrity engine is working!")
else:
    print("\nFAILED: Could not calculate hash.")
