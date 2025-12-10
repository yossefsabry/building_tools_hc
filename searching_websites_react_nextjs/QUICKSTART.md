# Quick Start Guide - React & Next.js Framework Finder

## What Changed

Your XSS target finder has been updated to **specifically detect React and Next.js frameworks** on bug bounty platforms. Results are automatically categorized into 4 separate files.

## Installation (Using uv - Recommended)

```bash
cd /home/yossef/tools/pull_website_nextjs/find-programs

# Install dependencies (automatically creates virtual environment)
uv sync
```

**Note:** If you're starting fresh or want to reinitialize:
```bash
uv init --no-readme
uv add requests selenium webdriver-manager wakepy python-dotenv
```

## Configuration

Create your `.env` file:

```bash
cp .env.example .env
nano .env  # or your preferred editor
```

Add your API keys:
```env
HACKERONE_API_KEY=your_identifier:your_token
BUGCROWD_API_KEY=your_api_key
```

## Running the Script

```bash
# Basic usage - scans both platforms
uv run react_nextjs_finder.py

# With detailed output
uv run react_nextjs_finder.py --verbose

# Only HackerOne
uv run react_nextjs_finder.py --hackerone

# Only Bugcrowd
uv run react_nextjs_finder.py --bugcrowd
```

## Output Files

The script creates 4 separate files:

1. **`hackerone_using_react.txt`** - React sites from HackerOne
2. **`hackerone_using_nextjs.txt`** - Next.js sites from HackerOne  
3. **`bugcrowd_using_react.txt`** - React sites from Bugcrowd
4. **`bugcrowd_using_nextjs.txt`** - Next.js sites from Bugcrowd

**Format:**
```
https://example.com -- 85 -- https://hackerone.com/program-name
```

## Real-Time Output

As the script finds frameworks, you'll see:

```
✓ FOUND [HACKERONE] [REACT]: https://example.com (Total: 5)
  Score: 75 -- Program: https://hackerone.com/example
```

## What's New

✅ **Next.js Detection** - Detects `__NEXT_DATA__`, `_next/static/`, and Next.js patterns  
✅ **Separate Output Files** - 4 files organized by platform and framework  
✅ **Real-Time Display** - Shows platform and framework type as results are found  
✅ **.env Support** - No more manual environment variable exports  
✅ **uv Integration** - Fast package management with automatic virtual environments  
✅ **Simplified Commands** - No more `--reflected-stored` or `--dom-based` flags

## Notes

- The script runs continuously - press **Ctrl+C** to stop
- Results are appended to files in real-time
- Prevents your system from sleeping while running
- Reuses existing program data to save API calls

---

For complete documentation, see [`README.md`](file:///home/yossef/tools/pull_website_nextjs/find-programs/README.md)
