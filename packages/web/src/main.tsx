import React from "react";
import ReactDOM from "react-dom/client";
import "./index.css";
import { App } from "./App.js";

const root = document.getElementById("root");
if (!root) throw new Error("#root not found");

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
