# AI Dev GitHub Push Checklist

**Quick checklist for each repository push**

## 🎯 Target Applications

- [ ] **ADAML-Pluto**: https://github.com/ro0TuX777/ADAML-Pluto.git
- [ ] **BCKraken**: https://github.com/ro0TuX777/BCKraken.git
- [ ] **Dashboard**: https://github.com/ro0TuX777/Dashboard.git

## ✅ Pre-Push Checklist (MANDATORY)

### **Repository Analysis**
- [ ] Navigate to application directory
- [ ] Check existing git status: `git status`
- [ ] Identify application type (Python/JS/Web/Data)
- [ ] List main files and structure

### **Critical Safety Check**
- [ ] **LARGE FILE SCAN**: `find . -type f -size +50M -not -path "./.git/*"`
- [ ] **RESULT**: No files over 50MB found ✅ / Large files found ⚠️
- [ ] If large files found: Add to .gitignore before proceeding

### **File Preparation**
- [ ] Create comprehensive .gitignore
- [ ] Create application-specific README.md
- [ ] Verify .gitignore excludes problematic files
- [ ] Test exclusions: `git status --ignored`

### **Git Setup**
- [ ] Initialize git: `git init` (if needed)
- [ ] Add GitHub remote: `git remote add github [URL]`
- [ ] Verify remote: `git remote -v`

### **Safe Staging**
- [ ] **NEVER use `git add .`**
- [ ] Add files selectively:
  - [ ] `git add README.md .gitignore`
  - [ ] `git add *.py` (Python apps)
  - [ ] `git add *.js *.html *.css` (Web apps)
  - [ ] `git add *.sh *.conf *.md`
- [ ] Verify staging: `git status`
- [ ] Check staged files: `git diff --cached --stat`

### **Final Safety Check**
- [ ] **REPEAT LARGE FILE CHECK**: `find . -type f -size +50M -not -path "./.git/*"`
- [ ] Verify no large files in staging: `git diff --cached --name-only`
- [ ] Confirm .gitignore working: `git check-ignore [problematic-file]`

### **Commit and Push**
- [ ] Create descriptive commit message
- [ ] Commit: `git commit -m "Initial [APP] release..."`
- [ ] Push: `git push -u github main`
- [ ] Verify success: Check GitHub repository

## 🚨 Emergency Commands

### **If Large File Committed**
```bash
# Remove from git history
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch [FILE_PATH]' \
  --prune-empty --tag-name-filter cat -- --all

# Force push
git push --force-with-lease github main
```

### **If Push Fails**
```bash
# Check what's causing issues
git ls-files | xargs ls -lh | sort -k5 -hr | head -10

# Reset if needed
git reset --hard HEAD
git clean -fd
```

## 📋 Application-Specific Notes

### **ADAML-Pluto**
- **Type**: ML/Data Application
- **Exclude**: `*.pkl`, `*.model`, `data/`, `datasets/`, `*.csv`
- **Include**: `*.py`, `requirements.txt`, `notebooks/`

### **BCKraken**
- **Type**: Security/Network Tool
- **Exclude**: `*.log`, `*.pcap`, `captures/`, `*.db`
- **Include**: `*.py`, `*.sh`, `configs/`, `rules/`

### **Dashboard**
- **Type**: Web Application
- **Exclude**: `node_modules/`, `*.log`, `uploads/`, `cache/`
- **Include**: `*.html`, `*.css`, `*.js`, `package.json`

## ✅ Success Verification

For each completed repository:
- [ ] Repository visible on GitHub
- [ ] README.md displays correctly
- [ ] No large files committed
- [ ] All essential files included
- [ ] Repository ready for public use

## 📞 Help References

- **Full Template**: `AI_DEV_GITHUB_PUSH_TEMPLATE.md`
- **BCKismet Example**: https://github.com/ro0TuX777/BCKismet
- **Workflow Guide**: BCKismet's `GITHUB_WORKFLOW_GUIDE.md`

---

**Complete one application at a time**  
**Always run safety checks**  
**Reference BCKismet for examples**
