import React, { useEffect, useState } from "react";
import StatsCards from "./StatsCards";
import FindingsTable from "./FindingsTable";
import Charts from "./Charts";
import "../styles/dashboard.css";
import { getFindings } from "../api"; // ✅ use this

const Dashboard = () => {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await getFindings();
        setFindings(data);
      } catch (error) {
        console.error("Error fetching findings:", error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  if (loading) return <p>Loading findings...</p>;

  return (
    <div id="dashboard">
      <h1>Cloud Compliance Dashboard</h1>
      <StatsCards findings={findings} />
      <Charts findings={findings} />
      <FindingsTable findings={findings} />
    </div>
  );
};

export default Dashboard;
