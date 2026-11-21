# design-sync notes: TENIX Exposure UI

Target project: claude.ai/design project "TENIX Exposure UI" (id in config.json). Shape: `package`, **synth-entry mode** (no library `dist/`, no Storybook): the app is a private Vite SPA, so the converter bundles a curated wrapper package.

## How the build is wired (do not "simplify" these)
- `.design-sync/src/primitives/*.tsx` and `.design-sync/src/tenix/*.tsx` are one-line `export * from` wrappers over `src/components/ui/*` and a chosen subset of `src/components/shared/*`. `provider.tsx` exports `TenixProvider` (MemoryRouter + I18nProvider + TooltipProvider), referenced by `cfg.provider`; it is excluded from the card list via `componentSrcMap.TenixProvider = null`.
- `componentSrcMap` lists every component name -> its wrapper file. It is generated (regex over the exports of each source file) because, once `componentSrcMap` is non-empty, the converter stops deriving components from src and uses only that map. **When a new component is added to `src/components/ui` or the chosen shared files, add a wrapper file and its names to the map**, or it will silently be missing.
- `Sidebar*` is mapped to `null` on purpose: the app has no sidebar (see tenix-exposure/CLAUDE.md), so those are unused template code. Do not bring them back without asking.
- `.design-sync/tsconfig.json` exists because the converter's alias plugin tries `stem + ''` first, so `@/utils`, `@/icons`, `@/i18n` (directories) resolve to the directory and esbuild fails. The file maps those three to their `index` files explicitly. Remove it only if the converter's `tsconfigPathsPlugin` is fixed.
- Run with `--entry ./dist/index.js` (a path that does not exist): it only tells the converter which folder is the package root. Expect `[NO_DIST]` in the log; it is not an error.
- `cssEntry` points at the compiled app CSS `dist/assets/index-<hash>.css`. **The hash changes on every `npm run build` of web**; after one, update `cssEntry` before the next sync. Do not rebuild `web/dist` casually: the production portal serves it.
- Config home is `web/` (where `.design-sync/` lives). Staged converter: `.ds-sync/` (gitignored; recreate from the skill dir, then `cd .ds-sync && npm i esbuild ts-morph @types/react`).
- Render check needs Playwright's own chromium (`npx playwright install chromium` in web/, plus OS libs via `install-deps`). The machine is the Ubuntu VM described in tenix-exposure/DEPLOY-VM.md.

## Preview policy
- 47 components have authored previews in `previews/` (core primitives and TENIX widgets, plus parts shown inside their parent). 148 compound sub-parts ship as floor cards on purpose; they cannot render outside their parent.
- Previews that are byte-identical copies of a parent (BreadcrumbLink/Separator = BreadcrumbItem; InputGroupButton/Input = InputGroupAddon; Pagination{Ellipsis,Item,Link} = Pagination; PopoverBody/Footer/Header = Popover) were graded from the parent's rendered sheet, not read one by one.
- Overlay components (Dialog, DialogFooter, Sheet, Tooltip, Popover*, Select) use `cfg.overrides.<Name> = {cardMode: "single", viewport}` so the open state is visible.
- `Table` is an unstyled primitive: its preview passes the same classes as the Overview page. `CardAction` is not used in previews because `CardHeader` is flex-col in this theme (the action does not float right). `PopoverFooter` goes inside `PopoverBody`.

## Known render warns
- `[RENDER_THIN]` on Dialog, DialogFooter, Sheet: the content is in a portal, so root text is empty. The sheets show them correctly.
- `[TOKENS_MISSING]` for `--accordion-panel-height`, `--collapsible-panel-height`, `--available-height`, `--anchor-width`, ... : Base UI sets these at runtime.
- `[FONT_REMOTE]` Outfit: loaded from Google Fonts at runtime.

## Re-sync risks
- Tailwind is compiled from the classes the app uses; a class that only an unused component needs may be absent from `_ds_bundle.css`, and the design agent can invent a class that does not exist. Conventions tell it to search `_ds_bundle.css` first.
- `cssEntry` hash (above). `componentSrcMap` completeness (above).
- Only the light theme exists in the product (`LIGHT_ONLY`); `dark:` classes are present in the CSS but unused.
- No git repository in this folder, so `.design-sync/` is not versioned anywhere: back it up or `git init` before relying on it.
- The three shared sets that were NOT imported because they call the API or router (CveSheet, DeviceSheet, SoftwareSheet, DataStatus, RequireAuth, header menu) are application screens, not library parts.
