# React & Next.js Framework Finder

A Python tool for identifying React and Next.js websites on bug bounty platforms (HackerOne and BugCrowd).

## Features

- Fetches public bug bounty programs from HackerOne and BugCrowd APIs
- Specifically detects React and Next.js frameworks
- Categorizes results by platform and framework type
- Creates separate output files for each combination
- Supports subdomain enumeration via certificate transparency
- Runs continuously to discover and test new targets
- Real-time display showing detected frameworks

## Installation

### Using uv (Recommended - Fast!)

`uv` is a blazing-fast Python package manager. Install dependencies with:

```bash
cd find-programs

# Install dependencies (uv handles virtual environments automatically)
uv sync

# Or if starting fresh, initialize the project first
uv init --no-readme
uv add requests selenium webdriver-manager wakepy python-dotenv
```

### Alternative: Using pip (Traditional Method)

If you prefer pip:

```bash
cd find-programs

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

### Option 1: Using .env File (Recommended)

Create a `.env` file in the `find-programs` directory:

```bash
cp .env.example .env
```

Then edit `.env` with your API keys:

```env
HACKERONE_API_KEY=identifier:token
BUGCROWD_API_KEY=your_api_key_here
```

### Option 2: Using Environment Variables

Set your API keys as environment variables:

```bash
export HACKERONE_API_KEY="identifier:token"
export BUGCROWD_API_KEY="your_bugcrowd_api_key"
```

At least one API key must be set for the tool to work.

### Getting Your HackerOne API Key

1. Log in to HackerOne
2. Go to Settings → API Tokens (https://hackerone.com/settings/api_token/edit)
3. Create a new API token or use an existing one
4. The format should be: `identifier:token`
   - Example: `abc123def456:1a2b3c4d5e6f7g8h9i0j`
5. Add to your `.env` file or set the environment variable:
   ```bash
   export HACKERONE_API_KEY="your_identifier:your_token"
   ```

### Getting Your BugCrowd API Key

1. Log in to BugCrowd
2. Go to Settings → API
3. Generate an API token
4. Add to your `.env` file or set the environment variable:
   ```bash
   export BUGCROWD_API_KEY="your_token"
   ```

## Usage

### Using uv (Recommended)

`uv run` automatically handles the virtual environment:

```bash
# Scan all programs from both platforms
uv run react_nextjs_finder.py

# With verbose output
uv run react_nextjs_finder.py --verbose

# Only HackerOne
uv run react_nextjs_finder.py --hackerone

# With subdomain enumeration
uv run react_nextjs_finder.py --subdomains
```

### Using pip/venv (Alternative)

If you installed with pip, activate the virtual environment first:
```bash
source venv/bin/activate
```

### Basic Usage

Scan all programs from both platforms:
```bash
uv run react_nextjs_finder.py
```

### Platform Selection

Use only HackerOne:
```bash
uv run react_nextjs_finder.py --hackerone
uv run react_nextjs_finder.py -H
```

Use only BugCrowd:
```bash
uv run react_nextjs_finder.py --bugcrowd
uv run react_nextjs_finder.py -B
```

### Subdomain Enumeration

Enable subdomain discovery for wildcard scopes:
```bash
uv run react_nextjs_finder.py --subdomains
```

### Verbose Mode

Enable detailed output showing why each target is accepted or rejected:
```bash
uv run react_nextjs_finder.py --verbose
uv run react_nextjs_finder.py -v
```

Verbose mode shows:
- **Per Program:**
  - Number of targets extracted from each program
  - List of first 5 targets (to avoid spam)
  - Summary of URLs tested and targets found per program
- **Per Target:**
  - Detected frameworks and technologies
  - Number of JavaScript files
  - Security controls (CSP, WAF, authentication)
  - Detailed reason for acceptance/rejection
  - Which URLs are being skipped (already tested)
- **Error Details:**
  - Full stack traces for debugging issues

## Output

The tool generates several types of output files:

### 1. Program Data
- `programs_YYYYMMDD_HHMMSS.json` - Contains all fetched program data and scope information

### 2. Framework-Specific Results (4 separate files)

Each file contains websites using the specific framework from the specific platform:

1. **`hackerone_using_react.txt`** - React sites from HackerOne
2. **`hackerone_using_nextjs.txt`** - Next.js sites from HackerOne
3. **`bugcrowd_using_react.txt`** - React sites from BugCrowd
4. **`bugcrowd_using_nextjs.txt`** - Next.js sites from BugCrowd

**Format:** Each line contains:
```
https://example.com -- 85 -- https://hackerone.com/program-name
```
- Target URL
- Score (0-100)
- Link to the bug bounty program

### Real-Time Console Output

As frameworks are detected, you'll see output like:
```
✓ FOUND [HACKERONE] [REACT]: https://example.com (Total: 5)
  Score: 75 -- Program: https://hackerone.com/example
```

or

```
✓ FOUND [BUGCROWD] [NEXTJS]: https://another-site.com (Total: 6)
  Score: 82 -- Program: https://bugcrowd.com/another-program
```

## Framework Detection

### React Detection
The tool looks for:
- React library signatures
- `_react` and `reactdom` references
- React-specific patterns in JavaScript

### Next.js Detection
The tool specifically identifies Next.js by looking for:
- `__NEXT_DATA__` script tags in HTML
- `_next/static/` paths in script sources
- `__next` global variable
- `next/router` and `next/link` imports in JavaScript

**Note:** Next.js sites will be categorized as Next.js, not React, even though Next.js is built on React.

## How It Works

1. Checks for existing program data and prompts user to reuse or fetch fresh
2. Fetches all public programs from configured platforms (if needed)
3. Extracts URL and wildcard scope targets
4. Randomly selects programs for testing
5. For each target:
   - Detects technology stack and frameworks
   - Specifically looks for React or Next.js
   - Calculates exploitability score
   - Saves to the appropriate output file based on platform and framework
   - Displays real-time results showing which framework was detected
6. Continues indefinitely with robust error handling
7. Handles connection errors gracefully without stopping

## Notes

- The tool uses a headless Chrome browser for JavaScript analysis (optional but recommended)
  - If ChromeDriver fails to initialize, the tool continues without browser-based checks
- Random delays are included to avoid rate limiting
- Results are appended to output files as they're discovered
- Press Ctrl+C to stop the tool gracefully
- Connection errors during target testing are handled automatically - the tool continues running
- Program data can be reused to save time and avoid unnecessary API calls
- **The tool automatically prevents your system from going to sleep while running** - sleep mode is restored when you stop the tool

## Troubleshooting

### ChromeDriver - Now Automatic! 🎉

The tool now **automatically downloads the correct ChromeDriver** version for your Chrome/Chromium browser!

- Detects your Chrome/Chromium version
- Downloads the matching ChromeDriver from official sources
- Caches it in `~/.chromedriver/vXXX/` for reuse
- Works with any version (115+), including the latest Chromium

**Just run the tool** and it will handle everything automatically on first run.

If you have issues:
```bash
rm -rf ~/.chromedriver/
rm -rf ~/.wdm/drivers/chromedriver
```

Then restart the tool - it will download fresh drivers.

### .env File Not Loading

Make sure:
1. The `.env` file is in the `find-programs` directory (same directory as the script)
2. The file is named exactly `.env` (not `env.txt` or `.env.example`)
3. There are no quotes around the values (unless part of the actual key)
4. Each line follows the format: `KEY=value`

### No Targets Found

- Check that your API keys are valid and have proper permissions
- Use `--verbose` mode to see detailed analysis of why targets are rejected
- Ensure you have internet connectivity
- Try running with just one platform first (e.g., `--hackerone`)

## Example Complete Workflow

```bash
# 1. Navigate to directory
cd find-programs

# 2. Install dependencies with uv
uv sync

# 3. Configure API keys
cp .env.example .env
# Edit .env with your API keys using your favorite editor
nano .env  # or vim, code, etc.

# 4. Run the script
uv run react_nextjs_finder.py --verbose

# 5. Check results
cat hackerone_using_react.txt
cat hackerone_using_nextjs.txt
cat bugcrowd_using_react.txt
cat bugcrowd_using_nextjs.txt
```
