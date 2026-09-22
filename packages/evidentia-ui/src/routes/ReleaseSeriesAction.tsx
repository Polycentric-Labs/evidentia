import { ReleaseOperationPanel } from "./ReleaseCadenceCollectAction";
export function ReleaseSeriesAction(props: {
  freshAuth: boolean;
  authInvalidated?: boolean;
  verifyAuth: () => Promise<boolean>;
}) {
  return <ReleaseOperationPanel {...props} kind="series" />;
}
