@echo off
title Security Scanner MVP
echo ========================================
echo    Security Scanner MVP - Demarrage
echo ========================================
echo.

:: Verifier Python
py --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Python n'est pas installe!
    pause
    exit /b 1
)

:: Verifier Node.js
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Node.js n'est pas installe!
    pause
    exit /b 1
)

echo [OK] Python et Node.js detectes
echo.

:: Creer le dossier data si necessaire
if not exist "data" mkdir data

:: Lancer le backend dans une nouvelle fenetre
echo [INFO] Demarrage du backend FastAPI sur http://localhost:8000
start "Backend - FastAPI" cmd /k "cd /d %~dp0backend && py -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

:: Attendre un peu que le backend demarre
timeout /t 3 /nobreak >nul

:: Lancer le frontend dans une nouvelle fenetre
echo [INFO] Demarrage du frontend Next.js sur http://localhost:3000
start "Frontend - Next.js" cmd /k "cd /d %~dp0frontend && npm run dev"

:: Attendre que le frontend soit pret
timeout /t 5 /nobreak >nul

echo.
echo ========================================
echo    Serveurs lances avec succes!
echo ========================================
echo.
echo  Frontend : http://localhost:3000
echo  Backend  : http://localhost:8000
echo  API Docs : http://localhost:8000/docs
echo.
echo  Fermez les fenetres CMD pour arreter.
echo ========================================
echo.

:: Ouvrir le navigateur
start http://localhost:3000

echo Appuyez sur une touche pour fermer cette fenetre...
pause >nul
