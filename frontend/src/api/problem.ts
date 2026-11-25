import axios from 'axios';

export interface Problem {
  status: number | null;
  message: string;
  correlationId: string | null;
}

const messages: Record<number, string> = {
  400: 'The request could not be understood. Check the supplied values.',
  401: 'Your session has ended. Please sign in again.',
  403: 'You do not have permission to perform this action.',
  404: 'The requested item could not be found.',
  409: 'The item changed or the request conflicts with its current state.',
  413: 'The request is too large.',
  422: 'One or more supplied values are not valid.',
  429: 'Too many attempts. Please wait before trying again.',
  503: 'The service is temporarily unavailable. Please try again.',
};

/** Never expose arbitrary response content or exception messages to the UI. */
export function mapProblem(error: unknown): Problem {
  if (!axios.isAxiosError(error)) {
    return { status: null, message: 'Something went wrong. Please try again.', correlationId: null };
  }
  const status = error.response?.status ?? null;
  const data: unknown = error.response?.data;
  const id = data && typeof data === 'object' && 'correlation_id' in data
    ? data.correlation_id : null;
  const correlationId = typeof id === 'string' && /^[A-Za-z0-9-]{1,128}$/.test(id) ? id : null;
  return {
    status,
    message: status === null ? 'Unable to reach the service. Please check your connection.'
      : messages[status] ?? 'The request could not be completed. Please try again.',
    correlationId,
  };
}
