# Fork Customization Notes

Purpose: record fork-specific customizations and merge cautions so future upstream syncs do not accidentally drop local behavior.

## Repository identity
- Fork repo: `moeacgx/new-api`
- Upstream repo: `QuantumNous/new-api`
- Main rule: when syncing upstream changes, preserve local fork behavior documented below unless explicitly retired.

## Confirmed fork-only customizations
The following two items are confirmed local customizations and should be treated as mandatory fork behavior unless explicitly changed later.

### 1) DefaultUseAutoGroup => token 默认 group = auto
Status: confirmed active customization

Why it exists:
- Local requirement is that when `DefaultUseAutoGroup` is enabled, newly created / default token group behavior should default to `auto` instead of staying on the upstream default behavior.

Git commit:
- `f0356738` — `fix: default token group to auto when DefaultUseAutoGroup is enabled`

Branch location:
- `origin/main`

Files involved:
- `web/src/components/table/tokens/modals/EditTokenModal.jsx`

Observed diff summary:
- Small frontend behavior change in token edit modal logic to make the default token group follow the local auto-group rule.

Merge caution:
- Upstream updates touching token modal, token group defaults, or auto-group UX may overwrite this behavior during merge/rebase.
- Before completing any upstream sync, re-check whether `EditTokenModal.jsx` still preserves the local rule above.

Verification checklist after sync:
1. Open token edit/create modal.
2. Enable the setting path related to `DefaultUseAutoGroup`.
3. Verify default token group behavior resolves to `auto` as expected.
4. If upstream changed the surrounding UI logic, manually re-apply the customization and test again.

### 2) 模型价格显示原价
Status: confirmed active customization

Why it exists:
- Local requirement is to preserve and display the original token-price values in the model pricing modal, so operators can compare discounted/current displayed price with original base token pricing.
- This is a deliberate fork customization for pricing display, not an upstream default behavior.
- The same customization branch also preserves auto-group chain display in the pricing modal.

Git commits:
- `e8039c53` — `feat: show original and cache pricing in model modal`
- `ec5436e7` — `refactor: simplify model pricing token columns`
- `8fe2f883` — `fix: restore auto group chain in model pricing modal`
- `bbb6cd7b` — `feat: show original token prices in pricing modal`

Branch location:
- `fix-model-pricing-display`
- `origin/fix-model-pricing-display`

Files involved:
- `web/src/helpers/utils.jsx`
- `web/src/components/table/model-pricing/modal/components/ModelPricingTable.jsx`

Observed diff summary:
- Adds `originalInputPrice`, `originalCompletionPrice`, and `originalCachePrice` derived from base `model_ratio`.
- Adds `getModelPricingColumns()` helper to normalize token pricing columns for modal rendering.
- Updates `ModelPricingTable.jsx` to render original prices as strikethrough `原价` under the current displayed price.
- Keeps `autoGroups` chain rendering in the model pricing modal.

Merge caution:
- Upstream changes touching pricing modal layout, model pricing helpers, token price formatting, or auto-group display can silently remove this comparison view.
- High-risk files during upstream sync:
  - `web/src/helpers/utils.jsx`
  - `web/src/components/table/model-pricing/modal/components/ModelPricingTable.jsx`

Verification checklist after sync:
1. Open the 模型价格 / model pricing modal for a model with group pricing.
2. Verify the modal still shows current token price columns for 提示 / 补全 / 缓存读取.
3. Verify original prices appear as strikethrough `原价` when original and displayed prices differ.
4. Verify cache original price also renders when applicable.
5. Verify `auto` group call chain still appears at the top when `autoGroups` is provided.

## Branch notes
- `origin/main` currently contains confirmed customization #1.
- `fix-model-pricing-display` / `origin/fix-model-pricing-display` currently contains confirmed customization #2.
- Do not treat these as accidental diffs; they are intentional fork-maintained custom behavior.

## Sync workflow recommendation
When syncing from upstream:
1. Fetch upstream and inspect `git log --left-right --cherry-pick --oneline origin/main...upstream/main`.
2. Read this file before merge/rebase.
3. After conflict resolution, explicitly verify each confirmed customization listed here.
4. Keep this file updated whenever a new fork-only behavior is added, removed, or superseded by upstream.

## Template for new entries
Copy this block when adding a new customization:

### N) <short customization name>
Status: active / retired / merged-upstream

Why it exists:
- <business reason>

Git commit:
- `<sha>` — `<subject>`

Branch location:
- `<branch>`

Files involved:
- `<path>`

Merge caution:
- <what upstream changes may overwrite>

Verification checklist after sync:
1. <step>
2. <step>
3. <expected result>
