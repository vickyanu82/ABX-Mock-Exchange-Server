#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <set>
#include "json.hpp"
#include<fstream>
#include<regex>

#pragma comment(lib, "ws2_32.lib") 

using json = nlohmann::json;

constexpr auto PACKET_SIZE = 17;

struct Packet {
	char symbol[4];           // Ticker symbol (4 bytes)
	char buySellIndicator;    // Buy/Sell Indicator (1 byte)
	int32_t quantity;         // Quantity (4 bytes, Big Endian)
	int32_t price;            // Price (4 bytes, Big Endian)
	int32_t sequence;

	void parsePacket(const char* buffer) {
		std::memcpy(symbol, buffer, 4);
		buySellIndicator = buffer[4];
		quantity = ntohl(*reinterpret_cast<const int32_t*>(buffer + 5)); // Big Endian to Host Endian
		price = ntohl(*reinterpret_cast<const int32_t*>(buffer + 9)); // Big Endian to Host Endian
		sequence = ntohl(*reinterpret_cast<const int32_t*>(buffer + 13)); // Big Endian to Host Endian
	}

	json toJson() const {
		json j;
		j["symbol"] = std::string(symbol, 4);  // Convert symbol to string
		j["buySell"] = std::string(1, buySellIndicator); // Convert buySell to string
		j["quantity"] = quantity;
		j["price"] = price;
		j["sequence"] = sequence;
		return j;
	}
};
class TcpClient
{
public:
	TcpClient(const std::string& server_ip, int server_port)
		:server_ip_(server_ip),server_port_(server_port),socket_fd_(INVALID_SOCKET){

	}
	~TcpClient()
	{
		WSACleanup();
		closeConnection();
	}

	bool connectToServer()
	{
		WSADATA wsa_data;
		if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
		{
			std::cerr << "WSAStartup failed!" << std::endl;
			return false;
		}
		socket_fd_ = socket(AF_INET, SOCK_STREAM, 0);
		if (socket_fd_ == INVALID_SOCKET)
		{
			std::cerr << "Socket creation failed!" << WSAGetLastError() << std::endl;
			return false;
		}
		sockaddr_in server_addr;
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(server_port_);
		inet_pton(AF_INET, server_ip_.c_str(), &server_addr.sin_addr);

		//connect to server
		if (connect(socket_fd_, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
		{
			std::cerr << "Connect to server failed!" << WSAGetLastError() << std::endl;
			return false;
		}

		std::cout << "Connected to server at " << server_ip_ << ":" << server_port_ << std::endl;
		return true;
	}
	bool send_request(uint8_t callType, uint8_t resendSeq = 0) {
		uint8_t payload[2];
		payload[0] = callType;    
		payload[1] = resendSeq;  

		if (socket_fd_ == INVALID_SOCKET) {
			std::cerr << "Socket not connected\n";
			return false;
		}

		int bytes_sent = send(socket_fd_, (const char*)payload, sizeof(payload), 0);
		if (bytes_sent == SOCKET_ERROR) {
			std::cerr << "send() failed! Error: " << WSAGetLastError() << std::endl;
			return false;
		}

		std::cout << "Request sent to server: callType=" << (int)callType
			<< ", resendSeq=" << (int)resendSeq << std::endl;

		return true;
	}
	void handleMissingPackets(const std::set<int32_t>& receivedSequences, int lastSeq) {
		bool missingfound = false;
		std::cout << "Checking for missing sequences...\n";
		for (int32_t seq = 1; seq <= lastSeq; ++seq) {
			if (receivedSequences.find(seq) == receivedSequences.end()) {
				std::cout << "Missing packet sequence: " << seq << std::endl;
				missingfound = true;
				//closeConnection();
				connectToServer();
				send_request(2, seq);
				recvAgainData();
			}
		}
		if (!missingfound)
		{
			std::cout << "No missing packet found!" << std::endl;
			closeConnection();
		}
	}
	void recvAgainData()
	{
		char buffer[PACKET_SIZE];
		std::set<int32_t> receivedSequences;
		int lastSequence = 0;


		int bytesReceived = recv(socket_fd_, buffer, PACKET_SIZE, 0);
		if (bytesReceived <= 0) {
			if (bytesReceived == 0) {
				std::cout << "Connection closed by the server.\n";
			}
			else {
				perror("recv failed");
			}
		}

		if (bytesReceived != PACKET_SIZE) {
			std::cerr << "Invalid packet size: " << bytesReceived << " bytes received. Expected 17 bytes.\n";
			return; 
		}


		Packet packet;
		packet.parsePacket(buffer);

		if (validatePacket(packet))
		{
			pkts.push_back(packet);
			// Handle the received packet
			std::cout << "Received Packet: Symbol: " << packet.symbol
				<< " Buy/Sell: " << packet.buySellIndicator
				<< " Quantity: " << packet.quantity
				<< " Price: " << packet.price
				<< " Sequence: " << packet.sequence << std::endl;
		}
		else
		{
			logInvalidPacket(packet);
		}
		closeConnection();
	}
	void recvData()
	{
		char buffer[PACKET_SIZE];
		std::set<int32_t> receivedSequences;
		int lastSequence = 0;

		while (true) {
			int bytesReceived = recv(socket_fd_, buffer, PACKET_SIZE, 0);
			if (bytesReceived <= 0) {
				if (bytesReceived == 0) {
					std::cout << "Connection closed by the server.\n";
				}
				else {
					perror("recv failed");
				}
				break;
			}

			if (bytesReceived != PACKET_SIZE) {
				std::cerr << "Invalid packet size: " << bytesReceived << " bytes received. Expected 17 bytes.\n";
				return;
			}

			Packet packet;
			packet.parsePacket(buffer);

			if (validatePacket(packet))
			{
				pkts.push_back(packet);
				// Handle the received packet
				std::cout << "Received Packet: Symbol: " << packet.symbol
					<< " Buy/Sell: " << packet.buySellIndicator
					<< " Quantity: " << packet.quantity
					<< " Price: " << packet.price
					<< " Sequence: " << packet.sequence << std::endl;

				receivedSequences.insert(packet.sequence);
				lastSequence = lastSequence > packet.sequence ? lastSequence : packet.sequence;
			}
			else
			{ 
				logInvalidPacket(packet);
			}
			
		}
		 //After receiving all available packets, check for missing sequences
		handleMissingPackets(receivedSequences, lastSequence);
	}
	void closeConnection()
	{
		if (socket_fd_ != INVALID_SOCKET)
		{
			closesocket(socket_fd_);
			WSACleanup();
			socket_fd_ = INVALID_SOCKET;
			std::cout << "Socket Closed!" << std::endl;
		}
	}
	void WriteToFile()
	{
		json jsonResponse = json::array();

		std::sort(pkts.begin(), pkts.end(), [](const Packet& a, const Packet& b) {
			return a.sequence < b.sequence;
			});

		for (const auto& pkt : pkts)
		{
			jsonResponse.push_back(pkt.toJson());
		}
		std::ofstream outFile("response_data.json");
		if (outFile.is_open()) {
			outFile << jsonResponse.dump(4); // Pretty-print the JSON with an indentation of 4 spaces
			outFile.close();
			std::cout << "Response data written to response_data.json" << std::endl;
		}
		else {
			std::cerr << "Failed to open file for writing." << std::endl;
		}
	}
private:
	std::string server_ip_;
	int server_port_;
	SOCKET socket_fd_;
	Packet recv_pkt;
	std::vector<Packet> pkts;

	bool validatePacket(const Packet& packet) {
		// Validate Symbol (ASCII, no null bytes)
		for (char c : packet.symbol) {
			if (c < 32 || c > 126) {
				std::cerr << "Invalid symbol: " << std::string(packet.symbol, 4) << "\n";
				return false;
			}
		}

		// Validate Buy/Sell Indicator
		if (packet.buySellIndicator != 'B' && packet.buySellIndicator != 'S') {
			std::cerr << "Invalid Buy/Sell indicator: " << packet.buySellIndicator << "\n";
			return false;
		}

		// Validate Quantity
		if (packet.quantity <= 0) {
			std::cerr << "Invalid quantity: " << packet.quantity << "\n";
			return false;
		}

		// Validate Price
		if (packet.price < 0 || packet.price > 1'000'000) {
			std::cerr << "Invalid price: " << packet.price << "\n";
			return false;
		}

		return true;
	}
	void logInvalidPacket(const Packet& packet) {
		std::cerr << "Invalid packet detected:\n"
			<< "Symbol: " << std::string(packet.symbol, 4) << "\n"
			<< "Buy/Sell: " << packet.buySellIndicator << "\n"
			<< "Quantity: " << packet.quantity << "\n"
			<< "Price: " << packet.price << "\n"
			<< "Sequence: " << packet.buySellIndicator << "\n";
	}
};

class IP
{
public:
	bool isValidIPv4(const std::string& ip) {
		std::regex ipv4Pattern(
			R"(^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$)"
		);
		return std::regex_match(ip, ipv4Pattern);
	}

	bool isValidIPv6(const std::string& ip) {
		std::regex ipv6Pattern(
			R"(^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
        R"(([0-9a-fA-F]{1,4}:){1,7}:|"
        R"(([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
        R"(([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
        R"(([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
        R"(([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
        R"(([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
        R"([0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
        R"(:((:[0-9a-fA-F]{1,4}){1,7}|:)|"
        R"((fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,})|"
        R"(::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|2[0-4][0-9]|"
        R"([0-1]?[0-9][0-9]?)\.){3,3}(25[0-5]|2[0-4][0-9]|[0-1]?"
        R"([0-9][0-9]?))|([0-9a-fA-F]{1,4}:){1,4}):([0-9a-fA-F]{1,4}))$)"
		);
		return std::regex_match(ip, ipv6Pattern);
	}
};

TcpClient* globalClientInstance = nullptr; // Pointer to the TcpClient instance

BOOL WINAPI ConsoleHandler(DWORD signal) {
	if (signal == CTRL_CLOSE_EVENT) {
		std::cout << "Console window is being closed. Cleaning up resources...\n";

		if (globalClientInstance) {
			globalClientInstance->closeConnection(); // Call the class method to close the socket
			std::cout << "Socket connection closed gracefully.\n";
		}

		return TRUE; // Signal handled
	}
	return FALSE; // Pass signal to the next handler
}

int main() {

	if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
		std::cerr << "Error: Unable to set console control handler.\n";
		return 1;
	}

	std::string ipAddress;
	IP ip{};
	bool validIP = false;
	// Ask user for server IP address
	TRYAGAIN:
	std::cout << "Enter server IP address: ";
	std::getline(std::cin, ipAddress);

	// Validate the IP address
	if (ip.isValidIPv4(ipAddress)) {
		validIP = true;
		std::cout << "Valid IPv4 address.\n";
	}
	else if (ip.isValidIPv6(ipAddress)) {
		validIP = true;
		std::cout << "Valid IPv6 address.\n";
	}
	else {
		validIP = false;
		std::cout << "Invalid IP address.\n";
	}

	if (!validIP)
	{
		goto TRYAGAIN;
	}

	std::string server_ip = ipAddress;
	int server_port = 3000;

	TcpClient client(server_ip, server_port);
	globalClientInstance = &client;

	if (!client.connectToServer())
	{
		return 1;
	}

	std::thread recv_thread([&client]() {
		client.recvData();
		});
	client.send_request(1);
	recv_thread.join();
	client.WriteToFile();

	globalClientInstance = nullptr;

	int c = getchar();
	return 0;
}