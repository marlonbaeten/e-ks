import { test as base, type Page } from "@playwright/test";
import { AuthorisedAgentsPage } from "./pages/authorisedAgentsPage";
import { ListSubmittersPage } from "./pages/listSubmittersPage";
import { SubstituteSubmittersPage } from "./pages/substituteSubmittersPage";
import { CandidateListsOverviewPage } from "./pages/candidateListsOverviewPage";
import { ManageCandidateListPage } from "./pages/manageCandidateListPage";

type Fixtures = {
  deleteExistingGeneralInformation: Page;
  deleteExistingCandidateLists: Page;
};

export const test = base.extend<Fixtures>({
  deleteExistingGeneralInformation: async ({ page }, use) => {
    await page.goto("/political-group/authorised-agents");
    await new AuthorisedAgentsPage(page).deleteExistingAuthorisedAgents();

    await page.goto("/political-group/list-submitters");
    await new ListSubmittersPage(page).deleteExistingListSubmitters();

    await new SubstituteSubmittersPage(
      page,
    ).deleteExistingSubstituteSubmitters();

    await use(page);
  },

  deleteExistingCandidateLists: async ({ page }, use) => {
    await page.goto("/candidate-lists");
    const candidateListsOverviewPage = new CandidateListsOverviewPage(page);
    for (const candidateList of await candidateListsOverviewPage.linkCandidateList.all()) {
      if (await candidateList.isVisible()) {
        await candidateList.click();
        await new ManageCandidateListPage(page).removeList();
      }
    }
    await use(page);
  }
});
