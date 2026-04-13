import React from "react";
import "../styles/table.css";

const FindingsTable = ({ findings }) => {
  return (
    <div id="findingsTable">
      <h3>Detailed Findings</h3>
      <table>
        <thead>
          <tr>
            <th>Resource Type</th>
            <th>Severity</th>
            <th>Title</th>
            <th>Timestamp</th>
            <th>Scanner</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr key={f.findingId}>
              <td>{f.resourceType}</td>
              <td>{f.severity}</td>
              <td>{f.title}</td>
              <td>{new Date(f.timestamp).toLocaleString()}</td>
              <td>{f.scanner}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default FindingsTable;
