#include <windows.h>   // for console unicode support
#include <iostream>
#include <fstream>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include <sstream>

using namespace std;

// packet structure
struct Packet {
    char sourceIP[20];
    char destIP[20];
    int sourcePort;
    int destPort;
    char payload[300];
};

// alert structure
struct Alert {
    char threatType[50];
    char sourceIP[20];
    char time[30];
};

Alert alerts[50];              // recent alerts in RAM
int alertCount = 0;
long long totalPackets = 0;    // total packets analyzed
long long totalThreatsHistory = 0;

const char* STATS_FILE = "nids_stats.txt";
const char* LOG_FILE   = "nids_logs.csv";

// checks basic IP format
bool isValidIP(char* ip) {
    int dots = 0;
    for (int i = 0; ip[i] != '\0'; i++)
        if (ip[i] == '.') dots++;
    return dots == 3;
}

// gets current system time
void getCurrentTime(char* timeStr) {
    time_t now = time(0);
    strcpy(timeStr, ctime(&now));
    timeStr[strlen(timeStr) - 1] = '\0';
}

// converts string to uppercase
void toUpper(char* str) {
    for (int i = 0; str[i]; i++)
        if (str[i] >= 'a' && str[i] <= 'z')
            str[i] -= 32;
}

// saves packet count to file
void saveTotalPackets() {
    ofstream file(STATS_FILE);
    if (file.is_open()) file << totalPackets;
}

// logs alert to CSV file
void logThreatToDisk(const char* type, const char* ip, const char* time) {
    ofstream file(LOG_FILE, ios::app);
    if (file.is_open())
        file << type << "," << ip << "," << time << "\n";
}

// loads saved stats and alerts
void loadSystemData() {

    ifstream statFile(STATS_FILE);
    if (statFile.is_open())
        statFile >> totalPackets;

    ifstream logFile(LOG_FILE);
    if (!logFile.is_open()) return;

    vector<string> lines;
    string line;
    while (getline(logFile, line))
        if (!line.empty()) lines.push_back(line);

    totalThreatsHistory = lines.size();
    int start = (lines.size() > 50) ? lines.size() - 50 : 0;

    for (size_t i = start; i < lines.size(); i++) {
        stringstream ss(lines[i]);
        string temp;

        getline(ss, temp, ',');
        strcpy(alerts[alertCount].threatType, temp.c_str());

        getline(ss, temp, ',');
        strcpy(alerts[alertCount].sourceIP, temp.c_str());

        getline(ss, temp, ',');
        strcpy(alerts[alertCount].time, temp.c_str());

        alertCount++;
    }
}

// SQL injection detection
bool detectSQLInjection(Packet* pkt) {

    char payload[300];
    strcpy(payload, pkt->payload);
    toUpper(payload);

    const char* patterns[] = {
        "' OR '1'='1",
        "UNION SELECT",
        "DROP TABLE",
        "'; DELETE"
    };

    for (int i = 0; i < 4; i++) {
        char p[50];
        strcpy(p, patterns[i]);
        toUpper(p);

        if (strstr(payload, p)) {
            char timeStr[30];
            getCurrentTime(timeStr);

            if (alertCount < 50) {
                strcpy(alerts[alertCount].threatType, "SQL Injection");
                strcpy(alerts[alertCount].sourceIP, pkt->sourceIP);
                strcpy(alerts[alertCount].time, timeStr);
                alertCount++;
            }

            logThreatToDisk("SQL Injection", pkt->sourceIP, timeStr);
            totalThreatsHistory++;

            cout << "\n⚠️ SQL Injection Detected from "
                 << pkt->sourceIP << endl;

            return true;
        }
    }
    return false;
}

// port scan detection
bool detectPortScan(Packet* pkt) {

    int riskyPorts[] = {21, 22, 23, 80, 443, 3389, 3306, 5432};

    for (int port : riskyPorts) {
        if (pkt->destPort == port) {
            char timeStr[30];
            getCurrentTime(timeStr);

            if (alertCount < 50) {
                strcpy(alerts[alertCount].threatType, "Port Scan");
                strcpy(alerts[alertCount].sourceIP, pkt->sourceIP);
                strcpy(alerts[alertCount].time, timeStr);
                alertCount++;
            }

            logThreatToDisk("Port Scan", pkt->sourceIP, timeStr);
            totalThreatsHistory++;

            cout << "\n⚠️ Port Scan Detected on port "
                 << pkt->destPort << endl;

            return true;
        }
    }
    return false;
}

// analyzes a packet
void analyzePacket(Packet* pkt) {

    cout << "\nAnalyzing packet from "
         << pkt->sourceIP << endl;

    totalPackets++;
    saveTotalPackets();

    if (!detectSQLInjection(pkt))
        if (!detectPortScan(pkt))
            cout << "Packet is safe ✅" << endl;
}

// shows overall stats
void showStatistics() {
    cout << "\nPackets: " << totalPackets
         << "\nThreats: " << totalThreatsHistory << endl;
}

// shows recent alerts
void showAllAlerts() {
    for (int i = alertCount - 1; i >= 0; i--)
        cout << alerts[i].threatType << " | "
             << alerts[i].sourceIP << " | "
             << alerts[i].time << endl;
}

// manual packet entry
void manualEntry() {
    Packet pkt;

    cout << "Source IP: ";
    cin >> pkt.sourceIP;
    if (!isValidIP(pkt.sourceIP)) return;

    cout << "Source Port: ";
    cin >> pkt.sourcePort;

    cout << "Destination Port: ";
    cin >> pkt.destPort;

    cout << "Payload: ";
    cin.ignore();
    cin.getline(pkt.payload, 300);

    analyzePacket(&pkt);
}

// quick demo packets
void quickTest() {
    Packet pkt;
    int choice;

    cout << "1.SQLi  2.PortScan  3.Safe\nChoice: ";
    cin >> choice;

    if (choice == 1) {
        strcpy(pkt.sourceIP, "192.168.1.10");
        pkt.destPort = 3306;
        strcpy(pkt.payload, "admin' OR '1'='1");
    } else if (choice == 2) {
        strcpy(pkt.sourceIP, "203.0.113.5");
        pkt.destPort = 22;
        strcpy(pkt.payload, "SYN");
    } else {
        strcpy(pkt.sourceIP, "192.168.1.2");
        pkt.destPort = 8080;
        strcpy(pkt.payload, "Hello");
    }

    analyzePacket(&pkt);
}

// fixes console unicode output
void fixConsole() {
    SetConsoleOutputCP(CP_UTF8);
}

// program entry point
int main() {

    fixConsole();
    loadSystemData();

    int choice;
    do {
        cout << "\n1.Manual 2.Test 3.Stats 4.Alerts 0.Exit\nChoice: ";
        cin >> choice;

        if (choice == 1) manualEntry();
        else if (choice == 2) quickTest();
        else if (choice == 3) showStatistics();
        else if (choice == 4) showAllAlerts();

    } while (choice != 0);

    return 0;
}
