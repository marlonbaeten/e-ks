import type { Locator, Page } from "@playwright/test";

export class SubmitPage {
    readonly linkH1Download: Locator;

    constructor(protected readonly page: Page) {
        this.linkH1Download = this.page.getByRole('link', { name: 'H1 downloaden (Nederlands)' });
    }
}