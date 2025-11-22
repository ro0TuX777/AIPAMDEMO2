# Instructions for AI Dev - GitHub Repository Setup

**Task**: Push 3 local applications to their dedicated GitHub repositories  
**Based on**: Successful BCKismet deployment methodology

## 🎯 Repositories to Create

1. **ADAML-Pluto**: https://github.com/ro0TuX777/ADAML-Pluto.git
2. **BCKraken**: https://github.com/ro0TuX777/BCKraken.git
3. **Dashboard**: https://github.com/ro0TuX777/Dashboard.git

## 📋 Your Mission

Use the successful BCKismet push as a template to create professional GitHub repositories for each application. Each repository should be ready for public use with comprehensive documentation.

## 🛠️ Process for Each Application

### **Phase 1: Assessment**
1. **Navigate to application directory**
2. **Analyze the application structure** - identify type (Python, Web, ML, etc.)
3. **Run critical large file check**: `find . -type f -size +50M -not -path "./.git/*"`
4. **Document findings** - what type of app, main components, potential issues

### **Phase 2: Preparation**
1. **Create comprehensive .gitignore** based on application type
2. **Create professional README.md** with:
   - Application description
   - Features list
   - Installation instructions
   - Usage examples
   - Configuration details
3. **Verify exclusions work** before staging any files

### **Phase 3: Safe Deployment**
1. **Initialize git** (if needed): `git init`
2. **Add GitHub remote**: `git remote add github [REPO_URL]`
3. **Stage files selectively** (NEVER `git add .`)
4. **Run final safety check** for large files
5. **Commit with descriptive message**
6. **Push to GitHub**: `git push -u github main`

## 🚨 Critical Requirements

### **MUST DO:**
- ✅ Run large file detection before ANY git operations
- ✅ Create application-specific .gitignore
- ✅ Write comprehensive README.md for each app
- ✅ Stage files selectively, never use `git add .`
- ✅ Verify no files over 50MB are committed
- ✅ Test that .gitignore exclusions work

### **MUST NOT DO:**
- ❌ Commit any files over 50MB
- ❌ Use `git add .` - always add specific files
- ❌ Skip the large file safety check
- ❌ Create generic/minimal documentation
- ❌ Push without verifying staged files

## 📚 Reference Materials

### **Templates Available:**
- `AI_DEV_GITHUB_PUSH_TEMPLATE.md` - Complete methodology
- `AI_DEV_PUSH_CHECKLIST.md` - Step-by-step checklist
- BCKismet repository - Live example of successful implementation

### **Key Commands Reference:**
```bash
# Large file detection (CRITICAL)
find . -type f -size +50M -not -path "./.git/*"

# Safe file staging pattern
git add README.md .gitignore *.py *.sh *.conf *.md

# Verify staging
git status
git diff --cached --stat

# Emergency large file removal
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch [FILE_PATH]' \
  --prune-empty --tag-name-filter cat -- --all
```

## 🎯 Expected Deliverables

For each of the 3 repositories:

### **Repository Structure:**
```
[APPLICATION_NAME]/
├── README.md                 # Comprehensive documentation
├── .gitignore               # Application-specific exclusions
├── [application files]      # Core application code
├── [config files]          # Configuration files
├── [scripts]               # Setup/run scripts
└── [documentation]         # Additional docs if needed
```

### **README.md Must Include:**
- Clear application description
- Features and capabilities
- Installation instructions
- Usage examples
- Configuration details
- Contributing guidelines

### **Quality Standards:**
- Professional presentation
- Complete documentation
- No large files committed
- Proper file exclusions
- Ready for public use

## 🚀 Success Criteria

Each repository should be:
- ✅ **Accessible** - Public and properly configured
- ✅ **Complete** - All necessary files included
- ✅ **Documented** - Comprehensive README and setup instructions
- ✅ **Clean** - No large files, proper exclusions
- ✅ **Professional** - Ready for community use and contributions

## 📞 Support

- **Reference the BCKismet repository** for examples of successful implementation
- **Use the provided templates** for consistency
- **Follow the safety protocols** established in our workflow guides
- **Ask for clarification** if any application has unique requirements

---

**Priority**: Complete one application at a time  
**Quality over Speed**: Ensure each repository meets professional standards  
**Safety First**: Always run large file checks before committing

**Your goal**: Create 3 professional GitHub repositories that match the quality and completeness of the BCKismet repository.
