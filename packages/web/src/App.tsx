import { BrowserRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Layout } from "./components/Layout.js";
import { RunsPage } from "./pages/RunsPage.js";
import { NewRunPage } from "./pages/NewRunPage.js";
import { RunDetailPage } from "./pages/RunDetailPage.js";
import { ResultPage } from "./pages/ResultPage.js";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 5_000,
    },
  },
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<RunsPage />} />
            <Route path="runs/new" element={<NewRunPage />} />
            <Route path="runs/:id" element={<RunDetailPage />} />
            <Route path="runs/:id/results/:resultId" element={<ResultPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
