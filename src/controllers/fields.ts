import type { ArkimeClient } from '@/services/arkime-client.js';
import { formatFieldList } from '@/utils/formatters.js';
import type { ListFieldsParams } from '@/tools/schemas.js';

export async function listFields(client: ArkimeClient, params: ListFieldsParams) {
  const fields = await client.getFields();

  let filteredFields = fields;
  if (params.group) {
    filteredFields = fields.filter((f) => f.group === params.group);
  }

  const formatted = formatFieldList(filteredFields);

  return {
    content: [
      {
        type: 'text' as const,
        text: `Available Arkime fields:\n${formatted}`,
      },
    ],
  };
}
