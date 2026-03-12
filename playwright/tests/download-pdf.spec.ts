import { expect } from "@playwright/test";
import { test } from "./fixtures.ts";
import { CandidateListsOverviewPage } from "./pages/candidateListsOverviewPage.ts";
import { SelectElectoralDistrictsPage } from "./pages/selectElectoralDistrictsPage.ts";
import { ManageCandidateListPage } from "./pages/manageCandidateListPage.ts";


test.describe("download PDF", async () => {
    test("download H1", async ({ deleteExistingCandidateLists }) => {
             await deleteExistingCandidateLists.goto("/candidate-lists");
             await new CandidateListsOverviewPage(deleteExistingCandidateLists).buttonAddList.click();
        
             await new SelectElectoralDistrictsPage(deleteExistingCandidateLists).selectDistricts([
               "Drenthe"
             ]
         );
        
             const existingCandidates = ["Akwasi", "Braber"];
             const manageCandidateListPage = new ManageCandidateListPage(deleteExistingCandidateLists);
             await manageCandidateListPage.addExistingCandidates(existingCandidates);
        await deleteExistingCandidateLists.goto("/submit");
    });

});
