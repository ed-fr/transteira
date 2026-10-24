// Logic of SelectField, kept out of the component so that it is unit tested in Node.

/** One option of a select field. */
export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

/** A group of options (rendered as an <optgroup>). */
export interface SelectGroup {
  group: string;
  label: string;
  options: readonly SelectOption[];
}

/** An entry of a select field: an option or a group of options. */
export type SelectEntry = SelectOption | SelectGroup;

/** Reports whether entry is a group of options. */
export function isSelectGroup(entry: SelectEntry): entry is SelectGroup {
  return 'options' in entry;
}

/** Every option of the entries, groups flattened, in order. */
export function flattenOptions(entries: readonly SelectEntry[]): SelectOption[] {
  return entries.flatMap((entry) => (isSelectGroup(entry) ? [...entry.options] : [entry]));
}

/** Reports whether value is one of the options of the entries. */
export function hasOption(entries: readonly SelectEntry[], value: string): boolean {
  return flattenOptions(entries).some((option) => option.value === value);
}
