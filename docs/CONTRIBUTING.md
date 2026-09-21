# Contributing to TraceGuard

Thank you for your interest in contributing to TraceGuard! TraceGuard is an open-source cloud security investigation platform built with Next.js, Sanity, and Gemini AI.

## 1. Code of Conduct
We are committed to providing a friendly, safe, and welcoming environment for all. Please be respectful and professional in all interactions. Discriminatory, harassing, or otherwise unacceptable behavior will not be tolerated.

## 2. Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/TraceGuard.git
   cd TraceGuard
   ```
2. **Install dependencies:**
   ```bash
   npm install
   ```
3. **Set up environment variables:**
   Copy `.env.example` to `.env.local` and populate the required variables (see `DEPLOYMENT.md`).
4. **Start the development server:**
   ```bash
   npm run dev
   ```
   The app will be available at http://localhost:3000.

## 3. Project Structure
- `/app` - Next.js App Router pages and layouts
- `/lib` - Core application logic, scanners, rules, AI pipeline
- `/sanity` - Sanity Studio configuration, schema definitions
- `/components` - Reusable React components
- `/docs` - Project documentation
- `/public` - Static assets

## 4. Adding an AWS Scanner

To add a new AWS scanner (e.g., DynamoDB), follow these steps:

1. **Create the scanner file:** `lib/scanners/aws/dynamodb.ts`
   ```typescript
   import { ScanJob, ScanFinding } from '../../types';
   
   export async function scan(job: ScanJob): Promise<ScanFinding[]> {
     // Fetch data using AWS SDK v3
     // Evaluate findings
     return findings;
   }
   ```
2. **Add rules to:** `lib/scanners/rules/aws.ts`
   Define the specific security checks for the service.
3. **Add service key to:** `lib/scanners/aws/index.ts`
   Export the scanner so the engine can find it.
4. **Update engine display name:** `lib/scanners/engine.ts`
   Ensure the service is listed in the user interface correctly.

## 5. Adding a GCP Scanner

To add a new GCP scanner, follow a similar pattern:
1. Create `lib/scanners/gcp/newservice.ts`
2. Export the `scan(job: ScanJob)` function
3. Add rules to `lib/scanners/rules/gcp.ts`
4. Export in `lib/scanners/gcp/index.ts`
5. Update engine definitions in `lib/scanners/engine.ts`.

## 6. Adding Security Rules

Rules are centrally located in `lib/scanners/rules/aws.ts` and `lib/scanners/rules/gcp.ts`. Add your logic to evaluate specific configuration states against security best practices and compliance frameworks.

## 7. Sanity Schema Changes

To update the database schema:
1. Edit files in `/sanity/schemas/`
2. Run `npm run sanity:deploy` if deploying changes to production.
3. Seed data if necessary using provided scripts.

## 8. PR Guidelines
- Use descriptive commit messages.
- Fill out the PR template completely.
- Ensure all tests pass locally before requesting a review.
- Link relevant issues in the PR description.

## 9. TypeScript Standards
- **No `any`:** Avoid using `any` types. Define interfaces for all data structures.
- **No unused imports:** Keep files clean and organized.
- Follow existing project conventions for strict typing.
