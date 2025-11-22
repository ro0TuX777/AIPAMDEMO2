# AI Dev GitHub Push Template

**Template for pushing local applications to GitHub repositories**  
**Based on successful BCKismet deployment - November 2024**

## 🎯 Target Repositories

- **ADAML-Pluto**: https://github.com/ro0TuX777/ADAML-Pluto.git
- **BCKraken**: https://github.com/ro0TuX777/BCKraken.git  
- **Dashboard**: https://github.com/ro0TuX777/Dashboard.git

## 📋 Pre-Push Assessment Protocol

### **Step 1: Repository Analysis**
```bash
# Navigate to application directory
cd /path/to/application

# Analyze repository structure
ls -la
find . -type f -name "*.md" | head -10
find . -type f -name "*.py" | head -10
find . -type f -name "*.js" | head -10

# Check for existing git repository
git status 2>/dev/null || echo "No git repository found"
```

### **Step 2: Large File Detection (CRITICAL)**
```bash
# Find files over 50MB (GitHub limit is 100MB)
find . -type f -size +50M -not -path "./.git/*"

# Check for common problematic files
find . -name "*.db" -o -name "*.sqlite" -o -name "*.log" -o -name "*_data.json" | head -20

# List largest files
find . -type f -exec ls -lh {} \; | sort -k5 -hr | head -20
```

### **Step 3: Application Type Identification**
Identify the application type and create appropriate documentation:

**Python Applications:**
- Look for: `requirements.txt`, `setup.py`, `main.py`, `.venv/`
- Common exclusions: `__pycache__/`, `*.pyc`, `.venv/`, `*.log`

**JavaScript/Node Applications:**
- Look for: `package.json`, `node_modules/`, `*.js`
- Common exclusions: `node_modules/`, `npm-debug.log`, `*.log`

**Web Applications:**
- Look for: `index.html`, `css/`, `js/`, `static/`
- Common exclusions: `*.log`, `uploads/`, `cache/`

**Data/ML Applications:**
- Look for: `*.csv`, `*.json`, `models/`, `data/`
- Common exclusions: Large datasets, model files, `*.pkl`

## 🛠️ Implementation Steps

### **Step 1: Create Comprehensive .gitignore**
```bash
# Create .gitignore based on application type
cat > .gitignore << 'EOF'
# [APPLICATION_NAME] .gitignore
# Reference: Follow BCKismet pattern

# ========================================
# CRITICAL: Large Files (GitHub 100MB limit)
# ========================================
*.db
*.sqlite
*.sqlite3
*_data.json
*.log
*.pkl
*.model

# ========================================
# Application Specific (CUSTOMIZE BASED ON APP TYPE)
# ========================================
# Python
__pycache__/
*.pyc
*.pyo
.venv/
venv/

# Node.js
node_modules/
npm-debug.log*

# Data files
data/
datasets/
*.csv
*.xlsx

# ========================================
# Development Environment
# ========================================
.vscode/
.idea/
*.swp
*.swo

# ========================================
# Operating System Files
# ========================================
.DS_Store
Thumbs.db

# ========================================
# Backup and Temporary Files
# ========================================
*.bak
*.orig
*.tmp
*~
EOF
```

### **Step 2: Create Application README.md**
```bash
# Create comprehensive README.md
cat > README.md << 'EOF'
# [APPLICATION_NAME]

**[Brief description of the application]**

## 🚀 Features

- [Feature 1]
- [Feature 2]
- [Feature 3]

## 📋 Quick Start

### Prerequisites
- [List prerequisites]

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/ro0TuX777/[REPO_NAME].git
   cd [REPO_NAME]
   ```

2. [Installation steps specific to application type]

3. Run the application:
   ```bash
   [Command to run application]
   ```

## 🔧 Configuration

[Configuration details]

## 📖 Documentation

- [List documentation files]

## 🤝 Contributing

Contributions and improvements are welcome.

## 📄 License

[License information]

---

**Powered by [Organization/Team Name]**
EOF
```

### **Step 3: Initialize Git Repository**
```bash
# Initialize git if not already done
git init

# Add GitHub remote
git remote add github https://github.com/ro0TuX777/[REPO_NAME].git

# Verify remote
git remote -v
```

### **Step 4: Safe File Staging**
```bash
# CRITICAL: Run large file check first
find . -type f -size +50M -not -path "./.git/*"

# Add files selectively (NEVER use 'git add .')
git add README.md
git add .gitignore

# Add application-specific files based on type
# Python apps:
git add *.py requirements.txt setup.py

# JavaScript apps:
git add *.js *.html *.css package.json

# Configuration files:
git add *.conf *.config *.yml *.yaml

# Documentation:
git add *.md

# Scripts:
git add *.sh

# Verify what's staged
git status
git diff --cached --stat
```

### **Step 5: Commit and Push**
```bash
# Create initial commit
git commit -m "Initial [APPLICATION_NAME] release

- [List key features/components]
- [Configuration files included]
- [Documentation provided]
- [Any specific notes about the application]

Features:
- [Feature 1]
- [Feature 2]
- [Feature 3]"

# Push to GitHub
git push -u github main
```

## 🚨 Critical Safety Checks

### **Before Every Commit:**
```bash
# 1. Large file check
find . -type f -size +50M -not -path "./.git/*" && echo "⚠️  LARGE FILES FOUND - DO NOT COMMIT" || echo "✅ No large files"

# 2. Verify .gitignore working
git status --ignored

# 3. Check staged files
git diff --cached --name-only
```

### **Emergency Procedures:**
```bash
# If large file accidentally committed
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch [LARGE_FILE_PATH]' \
  --prune-empty --tag-name-filter cat -- --all

# Force push (CAUTION)
git push --force-with-lease github main
```

## 📝 Application-Specific Customizations

### **ADAML-Pluto (ML/Data Application)**
- Exclude: `*.pkl`, `*.model`, `data/`, `datasets/`, `*.csv`
- Include: `*.py`, `requirements.txt`, `notebooks/`, `configs/`

### **BCKraken (Security/Network Tool)**
- Exclude: `*.log`, `*.pcap`, `captures/`, `*.db`
- Include: `*.py`, `*.sh`, `configs/`, `rules/`

### **Dashboard (Web Application)**
- Exclude: `node_modules/`, `*.log`, `uploads/`, `cache/`
- Include: `*.html`, `*.css`, `*.js`, `package.json`, `static/`

## ✅ Success Criteria

- [ ] Repository successfully created on GitHub
- [ ] All application files properly committed
- [ ] No large files (>50MB) committed
- [ ] Comprehensive README.md created
- [ ] Proper .gitignore implemented
- [ ] Documentation includes setup instructions
- [ ] Repository is ready for public use

## 📞 Reference Materials

- **BCKismet Success Example**: https://github.com/ro0TuX777/BCKismet
- **GitHub Workflow Guide**: Reference BCKismet's `GITHUB_WORKFLOW_GUIDE.md`
- **Quick Reference**: Reference BCKismet's `GITHUB_QUICK_REFERENCE.md`

---

**Template Version**: 1.0  
**Based on**: BCKismet successful deployment  
**Last Updated**: November 2024
