# Overview

This is a Bitcoin signature vulnerability analysis tool designed for cybersecurity education. The application allows users to enter Bitcoin addresses, fetch unspent transaction outputs (UTXOs), decode raw Bitcoin transactions, and analyze ECDSA signatures for potential vulnerabilities like nonce reuse. The tool demonstrates how cryptographic weaknesses in Bitcoin signatures can lead to private key recovery in a controlled educational environment.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
The frontend is built with React and TypeScript using Vite as the build tool. It follows a component-based architecture with:

- **UI Framework**: Radix UI components with shadcn/ui styling system for consistent, accessible interface components
- **Styling**: Tailwind CSS with CSS variables for theming, configured with a dark theme by default
- **State Management**: React hooks with TanStack Query for server state management and caching
- **Routing**: Wouter for lightweight client-side routing
- **Form Handling**: React Hook Form with Zod validation for type-safe form management
- **Real-time Updates**: WebSocket integration for live analysis updates

The application structure includes specialized components for address analysis, transaction decoding, vulnerability scanning, and educational resources. The frontend communicates with the backend through REST APIs and WebSocket connections.

## Backend Architecture
The backend is an Express.js server with TypeScript that provides REST API endpoints for Bitcoin analysis operations:

- **Service-Oriented Design**: Separate services for Bitcoin operations, cryptographic analysis, and vulnerability detection
- **UTXO Fetching**: Multi-provider system that fetches unspent transaction outputs from Bitcoin addresses using blockchain APIs
- **Transaction Decoding**: Parses raw Bitcoin transaction hex data and extracts signature components for analysis
- **Vulnerability Analysis**: Implements ECDSA signature analysis including nonce reuse detection and private key recovery simulation
- **Real-time Communication**: WebSocket server for broadcasting analysis updates to connected clients

The server uses a modular approach with distinct services for Bitcoin operations, cryptographic analysis, and vulnerability testing, all designed for educational purposes with appropriate warnings.

## Data Storage Solutions
The application uses a flexible storage architecture:

- **Development Environment**: In-memory storage with Map-based implementations for rapid development
- **Production Environment**: PostgreSQL database with Neon serverless for scalable cloud deployment
- **ORM**: Drizzle ORM provides type-safe database operations with automatic schema generation
- **Database Schema**: Structured tables for users, analysis results, vulnerability patterns, API metrics, batch analysis, and educational content with JSONB fields for flexible data storage

The storage layer abstracts database operations through a unified interface, allowing seamless switching between development and production environments.

## Authentication and Authorization
Currently operates as a single-user educational tool without user authentication. The application includes:

- **Session Management**: Prepared for PostgreSQL session storage using connect-pg-simple
- **Educational Warnings**: Prominent warnings throughout the interface emphasizing the tool's educational purpose
- **Security Context**: Designed specifically for controlled educational environments with no real funds at risk

## API Design
The REST API follows standard HTTP conventions with comprehensive endpoints:

- **UTXO Analysis**: `POST /api/utxos` - Fetches and analyzes UTXOs for Bitcoin addresses across multiple blockchain APIs
- **Transaction Decoding**: `POST /api/decode-transaction` - Decodes raw transaction hex and extracts signature data
- **Vulnerability Testing**: `POST /api/vulnerability-test` - Performs comprehensive vulnerability analysis including nonce reuse detection
- **System Status**: `GET /api/status` - Returns API health status and analysis statistics
- **Educational Content**: CRUD operations for managing educational resources and vulnerability patterns

All endpoints implement consistent error handling, request validation using Zod schemas, and return structured JSON responses.

# External Dependencies

## Database Services
- **Neon Database**: Serverless PostgreSQL for production data storage with WebSocket support for real-time connections
- **Drizzle Kit**: Database migration and schema management tools

## Bitcoin Blockchain APIs
- **Blockchain.com API**: Primary provider for UTXO data and transaction information
- **Blockstream Esplora API**: Secondary provider for Bitcoin mainnet and testnet data
- **SoChain API**: Backup provider for additional reliability and cross-validation

## UI and Styling Libraries
- **Radix UI**: Comprehensive set of unstyled, accessible UI components
- **Tailwind CSS**: Utility-first CSS framework with custom theming
- **Lucide React**: Icon library for consistent iconography
- **React Hook Form**: Form state management with validation
- **Zod**: Type-safe schema validation for forms and API requests

## Development and Build Tools
- **Vite**: Fast build tool with hot module replacement and development server
- **TypeScript**: Type safety across frontend and backend
- **ESBuild**: Fast JavaScript bundler for production builds
- **PostCSS**: CSS processing with Tailwind CSS integration

## Cryptographic and Analysis Libraries
- **Node.js Crypto**: Built-in cryptographic functions for ECDSA signature analysis
- **Custom Cryptographic Analysis**: Implements nonce reuse detection and private key recovery algorithms for educational demonstration

## Real-time Communication
- **WebSocket (ws)**: Native WebSocket implementation for real-time analysis updates and client-server communication