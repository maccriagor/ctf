import subprocess
import csv
import os
import math
import statistics

# --- Configuration ---
DOCKER_IMAGE = "my-app"
INPUT_FILE = "input.txt"
OUTPUT_CSV = "benchmark_results.csv"

def run_benchmark():
    # 1. Check input file
    if not os.path.exists(INPUT_FILE):
        print(f"❌ Error: {INPUT_FILE} not found.")
        return

    with open(INPUT_FILE, "r") as f:
        lines = f.readlines()
        if not lines:
            print("❌ Error: input.txt is empty.")
            return

        try:
            n_iterations = int(lines[0].strip())
        except ValueError:
            print("❌ Error: First line must be integer.")
            return

        message_content = "".join(lines[1:])

    print(f"🚀 Running {n_iterations} iterations via Docker...")

    # Added 'cryp_size' right after 'Iter'
    header = [
        "Iter", "cryp_size", "K_KEM_Cyc", "K_KEM_ns", "K_SIG_Cyc", "K_SIG_ns",
        "Sign_Cyc", "Sign_ns", "Verify_Cyc", "Verify_ns",
        "E_Cyc", "E_ns", "D_Cyc", "D_ns"
    ]

    # Store results for statistics
    results = {key: [] for key in header[1:]}

    with open(OUTPUT_CSV, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(header)

        for i in range(n_iterations):
            process = subprocess.Popen(
                ["./app"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = process.communicate(input=message_content)

            cryp_size = 0
            raw_values = []
            found_data = False

            # Parse all stdout lines to safely catch both SIZES and DATA lines
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith("SIZES:"):
                    try:
                        sizes = [int(x) for x in line.replace("SIZES:", "").split(",") if x.strip()]
                        cryp_size = sum(sizes)
                    except ValueError:
                        pass
                elif line.startswith("DATA:"):
                    raw_values = line.replace("DATA:", "").split(",")
                    found_data = True

            if found_data:
                # Write current iteration row to CSV
                writer.writerow([i + 1, cryp_size] + raw_values)

                # Store numeric values for statistics
                results["cryp_size"].append(float(cryp_size))
                
                # Zip maps header[2:] (performance metrics) directly to raw_values
                for key, value in zip(header[2:], raw_values):
                    try:
                        results[key].append(float(value))
                    except ValueError:
                        pass
            else:
                print(f"⚠️ No DATA in iteration {i+1}")
                if stderr:
                    print(stderr)

            # Progress update
            if (i + 1) % max(1, n_iterations // 20) == 0:
                percent = int(((i + 1) / n_iterations) * 100)
                print(f"⏳ {percent}% ({i+1}/{n_iterations})")

        # --- Statistical Summary (AFTER loop) ---
        writer.writerow([])

        labels = ["Mean", "Median", "Std Dev", "Margin of Error", "95% CI"]
        summary_rows = {label: [label] for label in labels}

        n = n_iterations

        for key in header[1:]:
            data = results[key]

            if not data:
                for label in labels:
                    summary_rows[label].append("")
                continue

            mean_val = statistics.mean(data)
            median_val = statistics.median(data)
            
            # Handle edge case where std dev calculation requires > 1 data point
            std_dev = statistics.stdev(data) if len(data) > 1 else 0.0
            margin = 1.96 * std_dev / math.sqrt(n) if n > 0 else 0.0

            lower = mean_val - margin
            upper = mean_val + margin
            ci_str = f"[{round(lower, 2)}, {round(upper, 2)}]"

            summary_rows["Mean"].append(round(mean_val, 2))
            summary_rows["Median"].append(round(median_val, 2))
            summary_rows["Std Dev"].append(round(std_dev, 2))
            summary_rows["Margin of Error"].append(round(margin, 2))
            summary_rows["95% CI"].append(ci_str)

        # Write summary
        for label in labels:
            writer.writerow(summary_rows[label])

    print(f"✅ Done → {OUTPUT_CSV}")


if __name__ == "__main__":
    run_benchmark()
