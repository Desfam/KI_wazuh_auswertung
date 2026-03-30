import type { FindingGroup } from '../types';
import { FindingsTable } from '../components/FindingsTable';

type FindingsPageProps = {
  findings: FindingGroup[];
};

export function FindingsPage({ findings }: FindingsPageProps) {
  return <FindingsTable findings={findings} />;
}
