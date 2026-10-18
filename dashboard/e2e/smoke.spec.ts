import { test, expect } from '@playwright/test';
import * as path from 'path';

test.describe('AegisChain Trust Platform Dashboard Smoke Test', () => {
  test('navigates through all views and captures high-resolution screenshots', async ({ page }) => {
    // 1. Visit dashboard home
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Verify title and header
    await expect(page.locator('.brand-title')).toBeVisible();
    await expect(page.locator('text=Software Supply Chain Trust Engine & Admission Controller')).toBeVisible();

    // Verify Overview stats
    await expect(page.locator('text=Workloads Admitted')).toBeVisible();
    await expect(page.locator('text=Supply Chain Attacks Blocked')).toBeVisible();
    await expect(page.locator('text=Mean Trust Score')).toBeVisible();

    // Capture Overview screenshot
    const imgDir = path.resolve(process.cwd(), '../docs/img');
    await page.screenshot({ path: path.join(imgDir, 'dashboard-overview.png'), fullPage: true });

    // 2. Navigate to Provenance Graph
    await page.click('#tab-graph');
    await expect(page.locator('text=End-to-End Cryptographic Provenance Graph')).toBeVisible();
    await expect(page.locator('text=SLSA BUILD LEVEL 3')).toBeVisible();

    // Capture Provenance Graph screenshot
    await page.screenshot({ path: path.join(imgDir, 'provenance-graph.png'), fullPage: true });

    // 3. Navigate to Decision Ledger
    await page.click('#tab-decisions');
    await expect(page.locator('text=Cryptographic Ledger Hash Chain Inspector')).toBeVisible();
    await expect(page.locator('text=sample-app:v1.0.0').first()).toBeVisible();

    // Capture Decision Explorer screenshot
    await page.screenshot({ path: path.join(imgDir, 'decision-explorer.png'), fullPage: true });

    // 4. Navigate to Admission Simulator
    await page.click('#tab-simulator');
    await expect(page.locator('text=Interactive Admission Simulator & Policy Sandbox')).toBeVisible();
    await page.click('#btn-run-simulation');
    await expect(page.locator('text=ADMISSION PERMITTED (ALLOW)')).toBeVisible();

    // Capture Admission Simulator screenshot
    await page.screenshot({ path: path.join(imgDir, 'admission-simulator.png'), fullPage: true });

    // 5. Navigate to Dependency Risk Scorer
    await page.click('#tab-risk');
    await expect(page.locator('text=Dependency Risk Scorer (Heuristic AST Analyzer)')).toBeVisible();
    await expect(page.locator('text=crossenv').first()).toBeVisible();

    // Capture Risk Scorer screenshot
    await page.screenshot({ path: path.join(imgDir, 'risk-scorer.png'), fullPage: true });

    // 6. Navigate to Policy & Waivers
    await page.click('#tab-policies');
    await expect(page.locator('text=Active OPA Rego v1 Policies')).toBeVisible();
    await expect(page.locator('text=signature_required').first()).toBeVisible();
    await expect(page.locator('text=provenance_required').first()).toBeVisible();
  });
});
