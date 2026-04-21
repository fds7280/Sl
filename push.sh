#!/bin/bash

# ── Config ─────────────────────────────────────────────────────────────────
REPO_URL="git@github.com:fds7280/Sl.git"

# ── Colors ─────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}◈  S T A T E L O C K  — Git Push${NC}"
echo "──────────────────────────────────"

# ── Check if git is initialized ────────────────────────────────────────────
if [ ! -d ".git" ]; then
    echo -e "${YELLOW}No git repo found. Initializing...${NC}"
    git init
    git remote add origin "$REPO_URL"
    echo -e "${GREEN}Initialized and remote set.${NC}"
fi

# ── Check if remote exists ─────────────────────────────────────────────────
if ! git remote get-url origin &>/dev/null; then
    echo -e "${YELLOW}No remote found. Adding origin...${NC}"
    git remote add origin "$REPO_URL"
fi

# ── Ask for commit message ─────────────────────────────────────────────────
echo ""
read -p "Commit message (leave blank for 'update'): " MSG
if [ -z "$MSG" ]; then
    MSG="update"
fi

# ── Stage all changes ──────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Staging changes...${NC}"
git add .

# ── Show what's being committed ────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Files staged:${NC}"
git status --short

# ── Commit ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Committing...${NC}"
git commit -m "$MSG"

# ── Push ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Pushing to GitHub...${NC}"
git branch -M main
git push -u origin main

# ── Done ───────────────────────────────────────────────────────────────────
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ Pushed successfully!${NC}"
else
    echo ""
    echo -e "${RED}✗ Push failed. Check your SSH key or remote URL.${NC}"
    echo -e "${YELLOW}Run: ssh -T git@github.com  to test your SSH connection${NC}"
fi
